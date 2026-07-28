"""Python / PyPI manifests and lockfiles.

Manifests: ``requirements*.txt``, ``pyproject.toml`` (PEP 621, PEP 735 and Poetry),
``setup.cfg`` and ``Pipfile``.
Lockfiles: ``uv.lock``, ``poetry.lock`` and ``Pipfile.lock``.
"""

from __future__ import annotations

import configparser
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet

from icebergsca.core.errors import ParseError
from icebergsca.core.graph import Node, most_included, resolve
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.base import EcosystemSpec, FileSpec, build_dependencies

#: Dependency-group names that conventionally mean "not shipped". Anything not
#: listed here keeps its declared scope, because guessing wrong in the other
#: direction hides real dependencies.
_DEV_GROUPS = frozenset({"dev", "develop", "development", "lint", "typing", "docs"})
_TEST_GROUPS = frozenset({"test", "tests", "testing"})

#: pip options and requirement forms we deliberately do not follow. ``-r``/``-c``
#: includes are skipped here because the referenced file is discovered on its own
#: during the directory walk; following them too would double-count.
_SKIP_PREFIXES = ("-", "http://", "https://", "git+", "hg+", "svn+", "bzr+", "file:")

#: pip-compile and ``uv pip compile`` annotate every entry with the packages that
#: required it. A ``# via -r requirements.in`` means the user asked for it directly;
#: a bare package name means it was pulled in transitively.
_VIA_DIRECT = re.compile(r"^-[rc]\s|^-[rc]$")

#: pip options trailing a requirement — ``--hash=sha256:…`` above all. They are not
#: part of PEP 508, so they have to come off before ``Requirement`` sees the line, or
#: every hash-pinned entry in a compiled requirements file is silently dropped.
_TRAILING_OPTIONS = re.compile(r"\s--\S.*$", re.DOTALL)


def _normalise(name: str) -> str:
    """PEP 503 name normalisation.

    Applied at parse time rather than at output time so that ``Flask``, ``flask``
    and ``FLASK`` deduplicate into one package across manifests, and so the name we
    send to OSV is the one it indexes.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _scope_for_group(group: str) -> Scope:
    lowered = group.lower()
    if lowered in _TEST_GROUPS:
        return Scope.TEST
    if lowered in _DEV_GROUPS:
        return Scope.DEV
    return Scope.OPTIONAL


def _pin_from_specifier(spec: SpecifierSet) -> tuple[str | None, Pin]:
    """Extract an exact version from a PEP 440 specifier set, if there is one.

    Only a lone ``==``/``===`` without a wildcard counts as pinned. ``==1.2.*`` is a
    range wearing an equals sign and is treated as such.
    """
    exact = [s for s in spec if s.operator in ("==", "===")]
    if len(exact) == 1 and len(list(spec)) == 1 and not exact[0].version.endswith("*"):
        return exact[0].version, Pin.PINNED
    return None, Pin.UNRESOLVED


def _find_line(content: str, needle: str) -> int | None:
    """Best-effort line number for a name inside a structured file.

    TOML and INI parsers discard position information, so for SARIF output we fall
    back to locating the first line that mentions the package. Wrong occasionally,
    absent otherwise — and an approximate anchor beats a file-level result.
    """
    for number, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return number
    return None


def _dependency(
    raw: str,
    *,
    path: Path,
    scope: Scope,
    direct: bool,
    line: int | None,
) -> Dependency | None:
    """Build a Dependency from a PEP 508 requirement string, or None if unusable."""
    try:
        requirement = Requirement(raw)
    except InvalidRequirement:
        return None

    version, pin = _pin_from_specifier(requirement.specifier)
    constraint = str(requirement.specifier) or None
    return Dependency(
        ref=PackageRef(EcosystemId.PYPI, _normalise(requirement.name), version),
        scope=scope,
        direct=direct,
        source=SourceLocation(path, line),
        pin=pin,
        constraint=constraint,
    )


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    """Remove a trailing comment, following pip's rule.

    A ``#`` only starts a comment at the start of the line or after whitespace, so
    fragments such as ``pkg @ https://host/x.whl#sha256=...`` survive intact.
    """
    if line.startswith("#"):
        return ""
    match = re.search(r"\s#", line)
    return line[: match.start()] if match else line


def _join_continuations(content: str) -> list[tuple[int, str, list[str]]]:
    """Flatten a requirements file into (line number, requirement, via targets).

    Backslash continuations are joined, and each entry collects the indented
    ``# via`` comment block that pip-compile writes beneath it.
    """
    entries: list[tuple[int, str, list[str]]] = []
    lines = content.splitlines()
    index = 0

    while index < len(lines):
        raw = lines[index]
        start_line = index + 1
        stripped = _strip_comment(raw).strip()

        while stripped.endswith("\\") and index + 1 < len(lines):
            index += 1
            stripped = (
                stripped[:-1].strip() + " " + _strip_comment(lines[index]).strip()
            )

        index += 1
        if not stripped:
            continue

        # Collect the annotation block that follows: comment lines indented under
        # this entry, which pip-compile uses to record what required it.
        via: list[str] = []
        while index < len(lines):
            following = lines[index]
            if not following.strip().startswith("#"):
                break
            if following.strip() != "#" and not following.startswith((" ", "\t")):
                break
            body = following.strip().lstrip("#").strip()
            if body.startswith("via"):
                remainder = body[3:].strip()
                if remainder:
                    via.append(remainder)
            elif via or body:
                via.append(body)
            index += 1

        entries.append((start_line, stripped, [v for v in via if v]))

    return entries


def _parse_requirements(path: Path, content: str) -> list[Dependency]:
    dependencies: list[Dependency] = []

    for line_number, text, via in _join_continuations(content):
        if text.lower().startswith(_SKIP_PREFIXES):
            continue

        # An entry annotated only with other package names was pulled in
        # transitively; one annotated with "-r requirements.in" was asked for.
        direct = not via or any(_VIA_DIRECT.match(entry) for entry in via)

        dependency = _dependency(
            _TRAILING_OPTIONS.sub("", text).strip(),
            path=path,
            scope=Scope.RUNTIME,
            direct=direct,
            line=line_number,
        )
        if dependency is not None:
            dependencies.append(dependency)

    return dependencies


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------


def _poetry_constraint(spec: Any) -> str | None:
    """Normalise a Poetry dependency spec into a version constraint string.

    Poetry accepts either a bare string or a table. Path, URL and git dependencies
    have no version to check and are dropped.
    """
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        version = spec.get("version")
        return version if isinstance(version, str) else None
    return None


def _poetry_dependencies(
    table: dict[str, Any],
    *,
    path: Path,
    content: str,
    scope: Scope,
) -> list[Dependency]:
    dependencies: list[Dependency] = []

    for name, spec in table.items():
        if name.lower() == "python":  # the interpreter, not a package
            continue
        constraint = _poetry_constraint(spec)
        if constraint is None:
            continue

        # Poetry's caret and tilde operators are not PEP 440, so they cannot go
        # through packaging's parser. An exact-looking string is a pin; everything
        # else is kept verbatim for the resolver to handle later.
        version = constraint if re.fullmatch(r"\d[\w.!+-]*", constraint) else None
        dependencies.append(
            Dependency(
                ref=PackageRef(EcosystemId.PYPI, _normalise(name), version),
                scope=scope,
                direct=True,
                source=SourceLocation(path, _find_line(content, name)),
                pin=Pin.PINNED if version else Pin.UNRESOLVED,
                constraint=constraint,
            )
        )

    return dependencies


def _parse_pyproject(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(str(path), f"invalid TOML: {exc}") from exc

    dependencies: list[Dependency] = []

    def add_all(raw_specs: Any, scope: Scope) -> None:
        if not isinstance(raw_specs, list):
            return
        for raw in raw_specs:
            if not isinstance(raw, str):
                continue
            dependency = _dependency(
                raw,
                path=path,
                scope=scope,
                direct=True,
                line=_find_line(content, raw),
            )
            if dependency is not None:
                dependencies.append(dependency)

    project = data.get("project", {})
    if isinstance(project, dict):
        add_all(project.get("dependencies"), Scope.RUNTIME)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, specs in optional.items():
                add_all(specs, _scope_for_group(group))

    # PEP 735 dependency groups are development tooling by convention; they are
    # never installed as part of the distribution.
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group, specs in groups.items():
            add_all(specs, _scope_for_group(group) if group else Scope.DEV)

    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        add_all(build_system.get("requires"), Scope.BUILD)

    poetry = (
        data.get("tool", {}).get("poetry", {})
        if isinstance(data.get("tool"), dict)
        else {}
    )
    if isinstance(poetry, dict):
        runtime = poetry.get("dependencies")
        if isinstance(runtime, dict):
            dependencies += _poetry_dependencies(
                runtime, path=path, content=content, scope=Scope.RUNTIME
            )
        legacy_dev = poetry.get("dev-dependencies")
        if isinstance(legacy_dev, dict):
            dependencies += _poetry_dependencies(
                legacy_dev, path=path, content=content, scope=Scope.DEV
            )
        for group, table in (poetry.get("group") or {}).items():
            group_deps = table.get("dependencies") if isinstance(table, dict) else None
            if isinstance(group_deps, dict):
                dependencies += _poetry_dependencies(
                    group_deps,
                    path=path,
                    content=content,
                    scope=_scope_for_group(group),
                )

    return dependencies


# ---------------------------------------------------------------------------
# setup.cfg
# ---------------------------------------------------------------------------


def _parse_setup_cfg(path: Path, content: str) -> list[Dependency]:
    parser = configparser.ConfigParser()
    try:
        parser.read_string(content)
    except configparser.Error as exc:
        raise ParseError(str(path), f"invalid INI: {exc}") from exc

    dependencies: list[Dependency] = []

    def add_block(block: str, scope: Scope) -> None:
        for raw in block.splitlines():
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            dependency = _dependency(
                text,
                path=path,
                scope=scope,
                direct=True,
                line=_find_line(content, text),
            )
            if dependency is not None:
                dependencies.append(dependency)

    if parser.has_option("options", "install_requires"):
        add_block(parser.get("options", "install_requires"), Scope.RUNTIME)

    if parser.has_section("options.extras_require"):
        for group, block in parser.items("options.extras_require"):
            add_block(block, _scope_for_group(group))

    return dependencies


# ---------------------------------------------------------------------------
# Pipfile
# ---------------------------------------------------------------------------


def _parse_pipfile(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(str(path), f"invalid TOML: {exc}") from exc

    dependencies: list[Dependency] = []
    for section, scope in (("packages", Scope.RUNTIME), ("dev-packages", Scope.DEV)):
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            constraint = _poetry_constraint(spec)
            # Pipfile writes "*" for "any version", which is a constraint carrying
            # no information rather than a version.
            constraint = None if constraint in ("*", "") else constraint
            version = (
                constraint[2:] if constraint and constraint.startswith("==") else None
            )
            dependencies.append(
                Dependency(
                    ref=PackageRef(EcosystemId.PYPI, _normalise(name), version),
                    scope=scope,
                    direct=True,
                    source=SourceLocation(path, _find_line(content, name)),
                    pin=Pin.PINNED if version else Pin.UNRESOLVED,
                    constraint=constraint,
                )
            )
    return dependencies


# ---------------------------------------------------------------------------
# uv.lock
# ---------------------------------------------------------------------------


def _text(value: Any) -> str | None:
    """Accept a value only if it is genuinely a string.

    Lockfiles are third-party input: a malformed one must degrade to "we don't know"
    rather than propagate an int or a dict into a version field.
    """
    return value if isinstance(value, str) else None


def _uv_names(entries: Any) -> list[str]:
    """Pull the package names out of a uv dependency array.

    Entries are inline tables like ``{ name = "click", marker = "..." }``; only the
    name matters to us, and anything without one is skipped rather than guessed at.
    """
    if not isinstance(entries, list):
        return []
    return [
        _normalise(entry["name"])
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    ]


def _uv_children(package: dict[str, Any]) -> tuple[str, ...]:
    """Every package this one can pull in, including through its own extras.

    A locked extra is not hypothetical: uv only writes a package into the lock when
    something in the resolution actually required it, so ``coverage[toml]`` really
    does mean tomli is installed. Traversing only the plain ``dependencies`` array
    leaves such packages unreachable, and an unreachable node has to be assumed to
    ship — which is how a dev-only package ends up reported as a runtime one.
    """
    children = list(_uv_names(package.get("dependencies")))
    for entries in (package.get("optional-dependencies") or {}).values():
        children.extend(_uv_names(entries))
    return tuple(dict.fromkeys(children))


def _uv_is_root(package: dict[str, Any]) -> bool:
    """True for the project itself rather than one of its dependencies.

    uv marks the workspace member it locked for with an ``editable`` or ``virtual``
    source. Those entries seed the graph and are excluded from the results — a
    project is not its own dependency.
    """
    source = package.get("source")
    return isinstance(source, dict) and ("editable" in source or "virtual" in source)


def _parse_uv_lock(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(str(path), f"invalid TOML: {exc}") from exc

    packages = data.get("package")
    if not isinstance(packages, list):
        raise ParseError(str(path), "no [[package]] entries found")

    nodes: dict[str, Node] = {}
    seeds: dict[str, Scope] = {}

    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue

        name = _normalise(package["name"])
        version = _text(package.get("version"))

        if _uv_is_root(package):
            _collect_uv_seeds(package, seeds)
            continue

        # Resolution markers can produce two entries for one name at different
        # versions. Both are real and both get reported; only the first owns the
        # plain name, since that is what dependency edges refer to.
        key = name if name not in nodes else f"{name}#{len(nodes)}"
        nodes[key] = Node(
            key=key,
            name=name,
            version=version,
            children=_uv_children(package),
        )

    return build_dependencies(
        resolve(nodes, seeds), nodes, ecosystem=EcosystemId.PYPI, path=path
    )


def _collect_uv_seeds(root: dict[str, Any], seeds: dict[str, Scope]) -> None:
    """Record what the project asked for directly, and under which scope."""
    for name in _uv_names(root.get("dependencies")):
        seeds[name] = Scope.RUNTIME

    for group, entries in (root.get("optional-dependencies") or {}).items():
        scope = _scope_for_group(group)
        for name in _uv_names(entries):
            seeds.setdefault(name, scope)

    # PEP 735 groups live under metadata and are development tooling by definition.
    metadata = root.get("metadata")
    requires_dev = metadata.get("requires-dev") if isinstance(metadata, dict) else None
    if isinstance(requires_dev, dict):
        for group, entries in requires_dev.items():
            scope = _scope_for_group(group) if group else Scope.DEV
            for name in _uv_names(entries):
                seeds.setdefault(name, scope)


# ---------------------------------------------------------------------------
# poetry.lock
# ---------------------------------------------------------------------------

#: Poetry's own name for the runtime dependency group.
_POETRY_MAIN = "main"


def _poetry_lock_scope(package: dict[str, Any]) -> Scope:
    """Read a locked package's group.

    Poetry 2.x writes ``groups = ["main", "dev"]``; 1.x wrote ``category = "main"``.
    Neither is present in some 1.5-era files, in which case runtime is assumed —
    over-reporting rather than hiding something that ships.
    """
    groups = package.get("groups")
    if isinstance(groups, list) and groups:
        if _POETRY_MAIN in groups:
            return Scope.RUNTIME
        return most_included(_scope_for_group(str(group)) for group in groups)

    category = package.get("category")
    if isinstance(category, str) and category != _POETRY_MAIN:
        return _scope_for_group(category)

    return Scope.RUNTIME


def _parse_poetry_lock(path: Path, content: str) -> list[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(str(path), f"invalid TOML: {exc}") from exc

    packages = data.get("package")
    if not isinstance(packages, list):
        raise ParseError(str(path), "no [[package]] entries found")

    nodes: dict[str, Node] = {}
    seeds: dict[str, Scope] = {}

    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue

        name = _normalise(package["name"])
        children = tuple(
            _normalise(child)
            for child in (package.get("dependencies") or {})
            if isinstance(child, str)
        )
        nodes[name] = Node(
            key=name,
            name=name,
            version=_text(package.get("version")),
            children=children,
        )
        # poetry.lock records each package's group but not which were asked for
        # directly, so every entry seeds the graph at its own scope. The sibling
        # pyproject.toml supplies directness when the scanner merges the two.
        seeds[name] = _poetry_lock_scope(package)

    return build_dependencies(
        resolve(nodes, seeds), nodes, ecosystem=EcosystemId.PYPI, path=path
    )


# ---------------------------------------------------------------------------
# Pipfile.lock
# ---------------------------------------------------------------------------


def _parse_pipfile_lock(path: Path, content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ParseError(str(path), f"invalid JSON: {exc}") from exc

    dependencies: list[Dependency] = []
    source = SourceLocation(path)

    for section, scope in (("default", Scope.RUNTIME), ("develop", Scope.DEV)):
        table = data.get(section)
        if not isinstance(table, dict):
            continue
        for name, entry in table.items():
            raw = entry.get("version") if isinstance(entry, dict) else None
            version = raw[2:] if isinstance(raw, str) and raw.startswith("==") else None
            dependencies.append(
                Dependency(
                    ref=PackageRef(EcosystemId.PYPI, _normalise(name), version),
                    scope=scope,
                    # Pipfile.lock flattens direct and transitive together and does
                    # not distinguish them. The sibling Pipfile does, and the scanner
                    # merges that in; assuming direct here would be a guess.
                    direct=False,
                    source=source,
                    pin=Pin.PINNED if version else Pin.UNRESOLVED,
                    constraint=raw if isinstance(raw, str) else None,
                )
            )

    return dependencies


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def parse_manifest(path: Path, content: str) -> list[Dependency]:
    filename = path.name.lower()
    if filename == "pyproject.toml":
        return _parse_pyproject(path, content)
    if filename == "setup.cfg":
        return _parse_setup_cfg(path, content)
    if filename == "pipfile":
        return _parse_pipfile(path, content)
    return _parse_requirements(path, content)


def parse_lockfile(path: Path, content: str) -> list[Dependency]:
    filename = path.name.lower()
    if filename == "uv.lock":
        return _parse_uv_lock(path, content)
    if filename == "poetry.lock":
        return _parse_poetry_lock(path, content)
    return _parse_pipfile_lock(path, content)


SPEC = EcosystemSpec(
    id=EcosystemId.PYPI,
    manifests=FileSpec(
        names=frozenset({"pyproject.toml", "setup.cfg", "pipfile"}),
        patterns=("requirements*.txt",),
        parent_dirs=frozenset({"requirements"}),
    ),
    lockfiles=FileSpec(names=frozenset({"uv.lock", "poetry.lock", "pipfile.lock"})),
    parse_manifest=parse_manifest,
    parse_lockfile=parse_lockfile,
)
