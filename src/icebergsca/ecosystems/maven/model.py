"""Maven's own vocabulary, as data.

A POM is not a dependency list — it is a template. Versions may come from a parent,
from ``dependencyManagement``, from an imported BOM, or from a property defined three
files away. These types keep those pieces separate until they can be combined into an
effective POM, because collapsing them early is what makes Maven parsing wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Scopes that do not propagate to a dependency's own dependents. Maven's own rule:
#: your test dependencies are not mine, and provided ones come from the container.
NON_TRANSITIVE_SCOPES = frozenset({"test", "provided", "system"})

#: Maven's default when a dependency declares no scope.
DEFAULT_SCOPE = "compile"


@dataclass(frozen=True, slots=True)
class Coordinate:
    """A ``groupId:artifactId:version`` triple."""

    group: str
    artifact: str
    version: str | None = None

    @property
    def key(self) -> str:
        """Identity without the version — what conflict resolution operates on."""
        return f"{self.group}:{self.artifact}"

    def __str__(self) -> str:
        return f"{self.key}:{self.version}" if self.version else self.key


@dataclass(frozen=True, slots=True)
class RawDependency:
    """A ``<dependency>`` element, before versions and properties are resolved."""

    group: str
    artifact: str
    version: str | None = None
    #: Exactly what the element declared — empty when it declared nothing, which is
    #: not the same as declaring ``compile``. A dependencyManagement entry can supply
    #: the scope for an undeclared one, and collapsing the two here would hide that.
    scope: str = ""
    optional: bool = False
    #: ``group:artifact`` keys this dependency must not drag in, from ``<exclusions>``.
    exclusions: frozenset[str] = field(default_factory=frozenset)
    #: ``<type>import</type>`` inside dependencyManagement — a BOM, not a dependency.
    is_import: bool = False

    @property
    def key(self) -> str:
        return f"{self.group}:{self.artifact}"


@dataclass(frozen=True, slots=True)
class Pom:
    """One parsed POM file, with nothing inherited or interpolated yet."""

    coordinate: Coordinate
    parent: Coordinate | None = None
    properties: dict[str, str] = field(default_factory=dict)
    #: ``dependencyManagement`` entries, keyed by ``group:artifact``.
    managed: tuple[RawDependency, ...] = ()
    dependencies: tuple[RawDependency, ...] = ()
    #: ``<modules>`` of an aggregator POM.
    modules: tuple[str, ...] = ()
