"""The ecosystem registry.

To add an ecosystem: write a module exposing a ``SPEC``, then add it to
:data:`ECOSYSTEMS`. Nothing else in the codebase needs to know it exists.
"""

from __future__ import annotations

from pathlib import PurePath

from icebergsca.core.models import EcosystemId
from icebergsca.ecosystems import dotnet, golang, maven, npm, python, ruby, rust
from icebergsca.ecosystems.base import EcosystemSpec, FileKind

ECOSYSTEMS: tuple[EcosystemSpec, ...] = (
    python.SPEC,
    npm.SPEC,
    maven.SPEC,
    golang.SPEC,
    rust.SPEC,
    dotnet.SPEC,
    ruby.SPEC,
)

_BY_ID: dict[EcosystemId, EcosystemSpec] = {spec.id: spec for spec in ECOSYSTEMS}


def get(ecosystem: EcosystemId) -> EcosystemSpec:
    return _BY_ID[ecosystem]


def classify(path: PurePath) -> tuple[EcosystemSpec, FileKind] | None:
    """Identify a path as a manifest or lockfile, or return ``None`` if it is neither.

    The first ecosystem to claim the path wins. Registry order therefore matters
    only where two ecosystems would claim the same filename, which none currently do.
    """
    for spec in ECOSYSTEMS:
        kind = spec.kind_of(path)
        if kind is not None:
            return spec, kind
    return None


__all__ = ["ECOSYSTEMS", "classify", "get"]
