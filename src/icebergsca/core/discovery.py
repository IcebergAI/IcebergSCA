"""Finding the files worth scanning.

Walks a project tree, classifies every file against the ecosystem registry, and
groups the results into scan units — one ecosystem rooted at one directory, with its
manifests and any lockfiles sitting alongside them.

Everything skipped is recorded with a reason and surfaced in the report. A supply
chain tool that quietly drops a manifest looks exactly like one that found nothing
wrong with it.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from icebergsca.core.errors import DiscoveryError
from icebergsca.core.models import EcosystemId, SkippedFile
from icebergsca.ecosystems import classify
from icebergsca.ecosystems.base import FileKind

logger = logging.getLogger(__name__)

#: Directories never worth walking: installed dependencies, build output and tool
#: caches. Scanning ``node_modules`` would report the same packages the lockfile
#: already describes, thousands of times over.
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "bower_components",
        "vendor",
        "target",
        "dist",
        "build",
        "out",
        "bin",
        "obj",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".gradle",
        ".idea",
        ".vscode",
        "site-packages",
    }
)

#: ``package-lock.json`` for a large application genuinely reaches tens of megabytes,
#: so this is generous. Anything larger is a red flag rather than a dependency file.
MAX_FILE_BYTES = 20_000_000  # 20 MB

#: Upper bound on manifests in one scan, to keep a mistargeted run (``scan /``) from
#: walking forever.
MAX_FILES = 2_000


@dataclass(frozen=True, slots=True)
class DiscoveryOptions:
    """Everything that changes which files get picked up."""

    #: Glob patterns matched against paths relative to the scan root.
    exclude: tuple[str, ...] = ()
    #: Directory depth below the root, or ``None`` for unlimited.
    max_depth: int | None = None
    follow_symlinks: bool = False
    #: Restrict to these ecosystems, or ``None`` for all of them.
    ecosystems: frozenset[EcosystemId] | None = None
    max_file_bytes: int = MAX_FILE_BYTES
    max_files: int = MAX_FILES


@dataclass(frozen=True, slots=True)
class ScanUnit:
    """One ecosystem's files in one directory.

    Manifests and lockfiles are kept apart because the lockfile is authoritative:
    when both are present the manifest contributes only scope and directness, and
    the versions come from the lock.
    """

    ecosystem: EcosystemId
    directory: PurePath
    manifests: tuple[PurePath, ...] = ()
    lockfiles: tuple[PurePath, ...] = ()

    @property
    def has_lockfile(self) -> bool:
        return bool(self.lockfiles)

    @property
    def files(self) -> tuple[PurePath, ...]:
        return self.lockfiles + self.manifests


@dataclass(frozen=True, slots=True)
class Discovery:
    """Result of walking a project tree. Paths are relative to :attr:`root`."""

    root: Path
    units: tuple[ScanUnit, ...] = ()
    skipped: tuple[SkippedFile, ...] = field(default=())

    @property
    def file_count(self) -> int:
        return sum(len(unit.files) for unit in self.units)


def _is_excluded(relative: PurePath, patterns: tuple[str, ...]) -> bool:
    """True if a path matches any user-supplied exclude glob.

    Both the full relative path and the bare filename are tested, so ``--exclude
    '*.csproj'`` works as naively expected without needing a leading ``**/``.
    """
    return any(
        relative.match(pattern) or PurePath(relative.name).match(pattern)
        for pattern in patterns
    )


def discover(root: Path, options: DiscoveryOptions | None = None) -> Discovery:
    """Walk ``root`` and group every recognised file into scan units.

    ``root`` may be a single manifest rather than a directory, which makes
    ``icebergsca scan ./requirements.txt`` work without a special case elsewhere.
    """
    options = options or DiscoveryOptions()
    root = root.expanduser()

    if not root.exists():
        raise DiscoveryError(f"path does not exist: {root}")

    if root.is_file():
        return _discover_single_file(root, options)

    if not root.is_dir():
        raise DiscoveryError(f"not a file or directory: {root}")

    root = root.resolve()
    manifests: dict[tuple[EcosystemId, PurePath], list[PurePath]] = defaultdict(list)
    lockfiles: dict[tuple[EcosystemId, PurePath], list[PurePath]] = defaultdict(list)
    skipped: list[SkippedFile] = []
    seen = 0

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, followlinks=options.follow_symlinks
    ):
        current = Path(dirpath)
        relative_dir = PurePath(current.relative_to(root))
        depth = 0 if relative_dir == PurePath(".") else len(relative_dir.parts)

        # Prune in place so os.walk never descends into what we exclude — the whole
        # point of topdown, and the difference between a fast scan and walking
        # every node_modules on disk.
        if options.max_depth is not None and depth >= options.max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                name
                for name in dirnames
                if name.lower() not in DEFAULT_EXCLUDE_DIRS
                and not _is_excluded(relative_dir / name, options.exclude)
            ]

        for filename in sorted(filenames):
            relative = (
                PurePath(filename)
                if relative_dir == PurePath(".")
                else relative_dir / filename
            )

            match = classify(relative)
            if match is None:
                continue

            spec, kind = match
            if options.ecosystems is not None and spec.id not in options.ecosystems:
                continue
            if _is_excluded(relative, options.exclude):
                skipped.append(SkippedFile(Path(relative), "excluded by --exclude"))
                continue

            if seen >= options.max_files:
                skipped.append(
                    SkippedFile(
                        Path(relative), f"exceeds --max-files ({options.max_files})"
                    )
                )
                continue

            reason = _rejection_reason(current / filename, options)
            if reason is not None:
                skipped.append(SkippedFile(Path(relative), reason))
                continue

            seen += 1
            bucket = lockfiles if kind is FileKind.LOCKFILE else manifests
            bucket[(spec.id, relative_dir)].append(relative)

    return Discovery(
        root=root,
        units=_build_units(manifests, lockfiles),
        skipped=tuple(skipped),
    )


def _discover_single_file(path: Path, options: DiscoveryOptions) -> Discovery:
    """Handle a scan targeted at one file rather than a tree."""
    resolved = path.resolve()
    match = classify(PurePath(resolved.name))
    if match is None:
        raise DiscoveryError(f"not a recognised manifest or lockfile: {path}")

    spec, kind = match
    if options.ecosystems is not None and spec.id not in options.ecosystems:
        raise DiscoveryError(f"{path} belongs to an ecosystem excluded by --ecosystem")

    relative = PurePath(resolved.name)
    reason = _rejection_reason(resolved, options)
    if reason is not None:
        return Discovery(
            root=resolved.parent, skipped=(SkippedFile(Path(relative), reason),)
        )

    unit = ScanUnit(
        ecosystem=spec.id,
        directory=PurePath("."),
        manifests=() if kind is FileKind.LOCKFILE else (relative,),
        lockfiles=(relative,) if kind is FileKind.LOCKFILE else (),
    )
    return Discovery(root=resolved.parent, units=(unit,))


def _rejection_reason(path: Path, options: DiscoveryOptions) -> str | None:
    """Return why a file cannot be read, or ``None`` if it is fine."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return f"unreadable: {exc.strerror or exc}"
    if size > options.max_file_bytes:
        return f"exceeds size limit ({size:,} > {options.max_file_bytes:,} bytes)"
    return None


def _build_units(
    manifests: dict[tuple[EcosystemId, PurePath], list[PurePath]],
    lockfiles: dict[tuple[EcosystemId, PurePath], list[PurePath]],
) -> tuple[ScanUnit, ...]:
    """Pair manifests with the lockfiles in the same directory.

    A lockfile with no manifest is still a scan unit — ``Cargo.lock`` alone tells us
    everything we need, and refusing to scan it because ``Cargo.toml`` was excluded
    would be perverse.
    """
    keys = sorted(
        set(manifests) | set(lockfiles), key=lambda k: (str(k[1]), k[0].value)
    )
    return tuple(
        ScanUnit(
            ecosystem=ecosystem,
            directory=directory,
            manifests=tuple(sorted(manifests.get((ecosystem, directory), []), key=str)),
            lockfiles=tuple(sorted(lockfiles.get((ecosystem, directory), []), key=str)),
        )
        for ecosystem, directory in keys
    )
