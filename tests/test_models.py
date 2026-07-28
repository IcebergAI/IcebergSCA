"""Core model behaviour."""

from __future__ import annotations

import pytest

from icebergsca.core.models import (
    Advisory,
    EcosystemId,
    Finding,
    PackageRef,
    ScanStatus,
    SeverityLevel,
)
from tests.conftest import make_advisory, make_dependency, make_report

# ---------------------------------------------------------------------------
# Package URLs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "name", "version", "expected"),
    [
        (EcosystemId.PYPI, "requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
        (EcosystemId.NPM, "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
        (
            EcosystemId.NPM,
            "@angular/core",
            "17.0.0",
            "pkg:npm/%40angular/core@17.0.0",
        ),
        (
            EcosystemId.MAVEN,
            "org.apache.commons:commons-lang3",
            "3.12.0",
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        ),
        (
            EcosystemId.GO,
            "github.com/pkg/errors",
            "v0.9.1",
            "pkg:golang/github.com/pkg/errors@v0.9.1",
        ),
        (EcosystemId.CARGO, "serde", "1.0.0", "pkg:cargo/serde@1.0.0"),
        (
            EcosystemId.NUGET,
            "Newtonsoft.Json",
            "13.0.3",
            "pkg:nuget/Newtonsoft.Json@13.0.3",
        ),
        (EcosystemId.RUBYGEMS, "rails", "7.1.0", "pkg:gem/rails@7.1.0"),
    ],
)
def test_purl_per_ecosystem(
    ecosystem: EcosystemId, name: str, version: str, expected: str
) -> None:
    assert PackageRef(ecosystem, name, version).purl == expected


def test_purl_normalises_python_names() -> None:
    """PEP 503 normalisation, so Flask and flask are one package not two."""
    assert PackageRef(EcosystemId.PYPI, "Pydantic_Core", "2.0").purl.startswith(
        "pkg:pypi/pydantic-core@"
    )


def test_purl_without_version() -> None:
    assert PackageRef(EcosystemId.PYPI, "requests").purl == "pkg:pypi/requests"


def test_ecosystem_vocabularies_are_distinct() -> None:
    """The three names for Go disagree, which is exactly why they are derived."""
    assert EcosystemId.GO.value == "go"
    assert EcosystemId.GO.osv_name == "Go"
    assert EcosystemId.GO.purl_type == "golang"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_ranks_descend_from_critical() -> None:
    order = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.UNKNOWN,
        SeverityLevel.NONE,
    ]
    assert [level.rank for level in order] == sorted(
        (level.rank for level in order), reverse=True
    )


def test_unscored_advisory_is_unknown_not_none() -> None:
    """An advisory nobody scored is not the same as one scored zero."""
    assert Advisory(id="OSV-1", modified="x").level is SeverityLevel.UNKNOWN


def test_malicious_advisory_is_critical_even_unscored() -> None:
    """A package published to attack its consumers does not need a CVSS score."""
    advisory = Advisory(id="MAL-2024-1234", modified="x")
    assert advisory.is_malicious
    assert advisory.level is SeverityLevel.CRITICAL


def test_cve_ids_filters_aliases() -> None:
    advisory = make_advisory(aliases=("CVE-2024-0001", "GHSA-aaaa", "PYSEC-2024-1"))
    assert advisory.cve_ids == ("CVE-2024-0001",)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_packages_deduplicates_preserving_order() -> None:
    report = make_report(
        dependencies=(
            make_dependency("requests", path="a/requirements.txt"),
            make_dependency("flask", path="a/requirements.txt"),
            make_dependency("requests", path="b/requirements.txt"),
        )
    )
    assert [ref.name for ref in report.packages] == ["requests", "flask"]
    # The dependency list keeps both entries: provenance is the point.
    assert len(report.dependencies) == 3


def test_direct_and_transitive_counts() -> None:
    report = make_report(
        dependencies=(
            make_dependency("requests", direct=True),
            make_dependency("urllib3", direct=False),
            make_dependency("idna", direct=False),
        )
    )
    assert (report.direct_count, report.transitive_count) == (1, 2)


def test_counts_by_severity_orders_most_severe_first() -> None:
    findings = (
        Finding(
            PackageRef(EcosystemId.PYPI, "a"), make_advisory(level=SeverityLevel.LOW)
        ),
        Finding(
            PackageRef(EcosystemId.PYPI, "b"),
            make_advisory(level=SeverityLevel.CRITICAL),
        ),
        Finding(
            PackageRef(EcosystemId.PYPI, "c"), make_advisory(level=SeverityLevel.LOW)
        ),
    )
    counts = make_report(findings=findings).counts_by_severity()
    assert list(counts) == [SeverityLevel.CRITICAL, SeverityLevel.LOW]
    assert counts[SeverityLevel.LOW] == 2


def test_sorted_findings_puts_worst_first() -> None:
    findings = (
        Finding(
            PackageRef(EcosystemId.PYPI, "low"), make_advisory(level=SeverityLevel.LOW)
        ),
        Finding(
            PackageRef(EcosystemId.PYPI, "crit"),
            make_advisory(level=SeverityLevel.CRITICAL),
        ),
    )
    assert [
        f.package.name for f in make_report(findings=findings).sorted_findings()
    ] == [
        "crit",
        "low",
    ]


def test_report_is_incomplete_until_vulnerabilities_are_checked() -> None:
    """An empty findings list is not a clean result unless the lookup actually ran."""
    assert make_report().is_complete is False
    assert make_report(vulnerabilities_checked=True).is_complete is True


def test_scan_failures_make_a_report_incomplete() -> None:
    report = make_report(
        vulnerabilities_checked=True,
        status=ScanStatus.PARTIAL,
        scan_failed=(PackageRef(EcosystemId.PYPI, "requests", "2.31.0"),),
    )
    assert report.is_complete is False


def test_finding_sources_deduplicate_but_keep_distinct_locations() -> None:
    same = make_dependency("requests", path="a/requirements.txt", line=1)
    duplicate = make_dependency("requests", path="a/requirements.txt", line=1)
    elsewhere = make_dependency("requests", path="b/requirements.txt", line=9)

    finding = Finding(
        package=PackageRef(EcosystemId.PYPI, "requests", "2.31.0"),
        advisory=make_advisory(),
        introduced_by=(same, duplicate, elsewhere),
    )
    assert [str(location) for location in finding.sources] == [
        "a/requirements.txt:1",
        "b/requirements.txt:9",
    ]


def test_finding_is_direct_when_any_introducer_is_direct() -> None:
    finding = Finding(
        package=PackageRef(EcosystemId.PYPI, "requests", "2.31.0"),
        advisory=make_advisory(),
        introduced_by=(
            make_dependency("requests", direct=False, path="a.txt"),
            make_dependency("requests", direct=True, path="b.txt"),
        ),
    )
    assert finding.is_direct is True
