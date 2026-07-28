"""Ecosystem descriptors and the filename registry.

An ecosystem is plain data: which filenames identify its manifests and lockfiles,
and the two functions that turn those files into ``Dependency`` records. Adding an
ecosystem means writing one module and appending one entry to
``ecosystems/__init__.py`` — there is no base class to inherit from and no
registration side effect to remember.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatch
from pathlib import Path, PurePath

from icebergsca.core.errors import UnsupportedFileError
from icebergsca.core.graph import Node, Resolved
from icebergsca.core.models import (
    Dependency,
    EcosystemId,
    PackageRef,
    Pin,
    SourceLocation,
)

#: Parses one file's text into dependency records. Takes the path as well as the
#: content because parsers need it both for provenance and, for lockfiles that share
#: an ecosystem, to dispatch on the filename.
FileParser = Callable[[Path, str], list[Dependency]]


class FileKind(StrEnum):
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"


@dataclass(frozen=True, slots=True)
class FileSpec:
    """Identifies files of one kind by exact name, glob, or containing directory.

    Matching is case-insensitive throughout: ``Gemfile``, ``Cargo.toml`` and
    ``Pipfile.lock`` are all conventionally capitalised, and case-sensitive matching
    silently misses them on any repo that got the case slightly wrong.
    """

    #: Exact filenames, lowercase.
    names: frozenset[str] = frozenset()
    #: Glob patterns matched against the lowercased filename, e.g. ``*.csproj``.
    patterns: tuple[str, ...] = ()
    #: Directory names whose ``.txt`` children count — for the ``requirements/``
    #: convention, where files are named ``base.txt`` and ``dev.txt``.
    parent_dirs: frozenset[str] = frozenset()
    #: Suffix required when matching via :attr:`parent_dirs`.
    parent_dir_suffix: str = ".txt"

    def matches(self, path: PurePath) -> bool:
        filename = path.name.lower()
        if filename in self.names:
            return True
        if any(fnmatch(filename, pattern) for pattern in self.patterns):
            return True
        return bool(
            self.parent_dirs
            and path.parent.name.lower() in self.parent_dirs
            and filename.endswith(self.parent_dir_suffix)
        )


@dataclass(frozen=True, slots=True)
class EcosystemSpec:
    """Everything the scanner needs to know about one ecosystem."""

    id: EcosystemId
    manifests: FileSpec
    lockfiles: FileSpec
    parse_manifest: FileParser
    parse_lockfile: FileParser

    def kind_of(self, path: PurePath) -> FileKind | None:
        """Classify a path, or return ``None`` if it belongs to another ecosystem.

        Lockfiles win when a name matches both, which is how ``go.mod`` is handled:
        its require block already lists MVS-resolved transitive versions, so it is
        authoritative rather than merely declarative.
        """
        if self.lockfiles.matches(path):
            return FileKind.LOCKFILE
        if self.manifests.matches(path):
            return FileKind.MANIFEST
        return None


def build_dependencies(
    resolved: list[Resolved],
    nodes: Mapping[str, Node],
    *,
    ecosystem: EcosystemId,
    path: Path,
) -> list[Dependency]:
    """Convert resolved graph nodes into dependency records.

    Everything from a lockfile is :attr:`Pin.PINNED` by definition — that is the
    whole reason to prefer lockfiles. Parent keys are mapped back to package
    references here so that nothing downstream needs to know a lockfile's internal
    key scheme.
    """
    source = SourceLocation(path)
    return [
        Dependency(
            ref=PackageRef(ecosystem, entry.node.name, entry.node.version),
            scope=entry.scope,
            direct=entry.direct,
            source=source,
            pin=Pin.PINNED,
            parents=tuple(
                PackageRef(ecosystem, nodes[key].name, nodes[key].version)
                for key in entry.parents
                if key in nodes
            ),
        )
        for entry in resolved
    ]


def unimplemented(kind: str) -> FileParser:
    """Placeholder parser for file kinds a milestone has not reached yet.

    Fails with a clear, actionable message rather than returning an empty list. An
    empty dependency list is indistinguishable from a clean project, and this tool
    must never manufacture that impression.
    """

    def _parse(path: Path, content: str) -> list[Dependency]:
        raise UnsupportedFileError(str(path), f"{kind} parsing is not implemented yet")

    return _parse
