"""Maven and Gradle.

Split in two because Java has no lockfile: :mod:`parser` reads what a build file
declares, and :mod:`resolver` reconstructs everything beneath it from Maven Central.
"""

from icebergsca.core.models import EcosystemId
from icebergsca.ecosystems.base import EcosystemSpec, FileSpec, unimplemented
from icebergsca.ecosystems.maven.parser import parse_manifest
from icebergsca.ecosystems.maven.resolver import MavenResolver, MavenResult, MavenUnit

SPEC = EcosystemSpec(
    id=EcosystemId.MAVEN,
    manifests=FileSpec(
        names=frozenset({"pom.xml", "build.gradle", "build.gradle.kts"})
    ),
    lockfiles=FileSpec(),
    parse_manifest=parse_manifest,
    parse_lockfile=unimplemented("Maven lockfile"),
)

__all__ = ["SPEC", "MavenResolver", "MavenResult", "MavenUnit", "parse_manifest"]
