"""Go modules.

``go.mod`` is registered as a lockfile rather than a manifest because its require
block already lists the transitive versions selected by minimal version selection,
with ``// indirect`` marking the ones the user did not ask for directly. That is the
resolved graph, and no separate lockfile exists.

``go.sum`` is deliberately not used: it records every module version *considered*
during resolution, including ones that were never selected, so scanning it reports
vulnerabilities in code that was never built.
"""

from __future__ import annotations

import re
from pathlib import Path

from icebergsca.core.errors import ParseError
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    Scope,
    SourceLocation,
)
from icebergsca.ecosystems.base import EcosystemSpec, FileSpec, unimplemented

#: ``require github.com/pkg/errors v0.9.1 // indirect``
_REQUIRE = re.compile(
    r"^(?P<module>[^\s]+)\s+(?P<version>v[^\s]+)(?P<comment>\s*//.*)?$"
)

#: ``replace old => new v1.2.3`` — the right-hand side is what actually builds.
_REPLACE = re.compile(r"^(?P<left>\S+)(?:\s+\S+)?\s*=>\s*(?P<right>.+)$")

#: Directives that may open a parenthesised block.
#:
#: Note on versions: a pseudo-version encodes a commit rather than a release
#: (``v0.0.0-20191109021931-daa7c04131f5``). OSV cannot match one to a range, but the
#: module is still worth querying, so the version is kept as-is.
_BLOCK_KEYWORDS = ("require", "replace", "exclude", "retract")


def _strip_comment(line: str) -> str:
    index = line.find("//")
    return line if index == -1 else line[:index].rstrip()


def _parse_go_mod(path: Path, content: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    replacements: dict[str, tuple[str, str | None]] = {}
    block: str | None = None

    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue

        if block is None:
            keyword = line.split()[0] if line.split() else ""
            if keyword in _BLOCK_KEYWORDS:
                remainder = line[len(keyword) :].strip()
                if remainder.startswith("("):
                    block = keyword
                    continue
                line = remainder
            elif keyword in ("module", "go", "toolchain"):
                continue
            else:
                continue
            current = keyword
        else:
            if line == ")":
                block = None
                continue
            current = block

        if current == "replace":
            # ``=> new v1.2.3 // use our fork`` is ordinary in the wild, and the
            # right-hand side is greedy: without stripping the comment first the
            # version fails to parse and the module is dropped from the scan
            # altogether rather than being reported under either name.
            match = _REPLACE.match(_strip_comment(line))
            if match:
                left = match.group("left").strip()
                right = match.group("right").strip().split()
                # A filesystem replacement has no version and nothing to query.
                if len(right) == 2 and right[1].startswith("v"):
                    replacements[left] = (right[0], right[1])
                else:
                    replacements[left] = (right[0], None)
            continue

        if current != "require":
            continue

        match = _REQUIRE.match(line)
        if match is None:
            continue

        module = match.group("module")
        indirect = "indirect" in (match.group("comment") or "")
        dependencies.append(
            Dependency(
                ref=PackageRef(EcosystemId.GO, module, match.group("version")),
                scope=Scope.RUNTIME,
                direct=not indirect,
                source=SourceLocation(path, number),
                pin=Pin.PINNED,
            )
        )

    # A module with no dependencies is legitimate; a file we failed to read is not.
    # Only complain when there was nothing recognisable in it at all.
    if not dependencies and "require" not in content and "module " not in content:
        raise ParseError(str(path), "no module declaration or require block found")

    return _apply_replacements(dependencies, replacements)


def _apply_replacements(
    dependencies: list[Dependency], replacements: dict[str, tuple[str, str | None]]
) -> list[Dependency]:
    """Rewrite modules that a ``replace`` directive redirects elsewhere.

    What ships is the replacement, so that is what gets checked. A replacement
    pointing at a local directory has nothing to look up and is dropped, since
    reporting the original would attribute advisories to code that is not built.
    """
    if not replacements:
        return dependencies

    result: list[Dependency] = []
    for dep in dependencies:
        target = replacements.get(dep.ref.name)
        if target is None:
            result.append(dep)
            continue
        module, version = target
        if version is None:
            continue
        result.append(
            Dependency(
                ref=PackageRef(EcosystemId.GO, module, version),
                scope=dep.scope,
                direct=dep.direct,
                source=dep.source,
                pin=Pin.PINNED,
            )
        )
    return result


SPEC = EcosystemSpec(
    id=EcosystemId.GO,
    manifests=FileSpec(),
    lockfiles=FileSpec(names=frozenset({"go.mod"})),
    parse_manifest=unimplemented("Go manifest"),
    parse_lockfile=_parse_go_mod,
)
