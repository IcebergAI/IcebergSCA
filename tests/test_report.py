"""Report renderers.

The most important assertions here are the negative ones: what the output must
*never* say when the vulnerability lookup did not run or did not finish.
"""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

import pytest

from icebergsca.core.errors import IcebergSCAError
from icebergsca.core.models import (
    EcosystemId,
    Finding,
    ManifestResult,
    PackageRef,
    ScanStatus,
    SeverityLevel,
    SkippedFile,
)
from icebergsca.report import OutputFormat, render
from tests.conftest import make_advisory, make_dependency, make_report


def finding(
    name: str = "requests",
    level: SeverityLevel = SeverityLevel.HIGH,
    fixed: str | None = "2.32.0",
) -> Finding:
    dep = make_dependency(name)
    return Finding(
        package=dep.ref,
        advisory=make_advisory(level=level),
        fixed_version=fixed,
        introduced_by=(dep,),
    )


def table_of(report_kwargs: dict[str, object]) -> str:
    return render(
        make_report(**report_kwargs), OutputFormat.TABLE, color=False, width=120
    )


# ---------------------------------------------------------------------------
# Not saying "clean" when nothing was checked
# ---------------------------------------------------------------------------


def test_table_does_not_claim_clean_when_lookup_never_ran() -> None:
    output = table_of({"dependencies": (make_dependency(),)})
    assert "did not run" in output
    assert "No known vulnerabilities" not in output


def test_table_reports_clean_only_after_a_real_check() -> None:
    output = table_of(
        {"dependencies": (make_dependency(),), "vulnerabilities_checked": True}
    )
    assert "No known vulnerabilities in 1 package(s)" in output


def test_table_never_reads_as_clean_when_nothing_could_be_checked() -> None:
    """ "No known vulnerabilities in 0 packages" reads as reassurance. It is not."""
    output = table_of(
        {
            "dependencies": (make_dependency(),),
            "vulnerabilities_checked": True,
            "scan_failed": (PackageRef(EcosystemId.PYPI, "requests", "2.31.0"),),
        }
    )
    assert "No known vulnerabilities" not in output
    assert "This is not a clean result" in output


def test_table_qualifies_a_clean_result_when_packages_went_unchecked() -> None:
    output = table_of(
        {
            "dependencies": (make_dependency("requests"), make_dependency("flask")),
            "vulnerabilities_checked": True,
            "scan_failed": (PackageRef(EcosystemId.PYPI, "flask", "2.31.0"),),
        }
    )
    assert "incomplete" in output


def test_json_flags_whether_the_lookup_ran() -> None:
    document = json.loads(render(make_report(), OutputFormat.JSON))
    assert document["scan"]["vulnerabilities_checked"] is False
    assert document["scan"]["complete"] is False


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------


def test_table_lists_findings_worst_first() -> None:
    output = table_of(
        {
            "vulnerabilities_checked": True,
            "findings": (
                finding("low-pkg", SeverityLevel.LOW),
                finding("crit-pkg", SeverityLevel.CRITICAL),
            ),
        }
    )
    assert output.index("crit-pkg") < output.index("low-pkg")


def test_table_shows_the_cve_rather_than_the_ghsa_id() -> None:
    output = table_of({"vulnerabilities_checked": True, "findings": (finding(),)})
    assert "CVE-2024-0001" in output


def test_table_names_the_file_actually_parsed() -> None:
    """After a lockfile falls back to its manifest, the manifest is what we read."""
    output = table_of(
        {
            "manifests": (
                ManifestResult(
                    ecosystem=EcosystemId.PYPI,
                    directory=Path("."),
                    manifests=(Path("pyproject.toml"),),
                    lockfiles=(Path("uv.lock"),),
                    parsed=(Path("pyproject.toml"),),
                    from_lockfile=False,
                ),
            )
        }
    )
    assert "pyproject.toml" in output
    assert "uv.lock" not in output


def test_table_reports_skipped_files() -> None:
    output = table_of(
        {"skipped": (SkippedFile(Path("huge.lock"), "exceeds size limit"),)}
    )
    assert "huge.lock" in output
    assert "exceeds size limit" in output


def test_table_reports_warnings() -> None:
    assert "falling back" in table_of({"warnings": ("falling back to pyproject.toml",)})


def test_table_without_color_has_no_escape_codes() -> None:
    output = table_of({"vulnerabilities_checked": True, "findings": (finding(),)})
    assert "\x1b[" not in output


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_document_shape() -> None:
    report = make_report(
        status=ScanStatus.OK,
        vulnerabilities_checked=True,
        dependencies=(make_dependency(),),
        findings=(finding(),),
    )
    document = json.loads(render(report, OutputFormat.JSON))

    assert document["schema_version"] == "1.0"
    assert document["tool"]["name"] == "icebergsca"
    assert document["summary"]["findings"] == 1
    assert document["summary"]["by_severity"] == {"high": 1}

    entry = document["findings"][0]
    assert entry["package"]["purl"] == "pkg:pypi/requests@2.31.0"
    assert entry["fixed_version"] == "2.32.0"
    assert entry["advisory"]["severity"]["level"] == "high"
    assert entry["introduced_by"][0]["path"] == "requirements.txt"


def test_json_records_dependency_pin_and_constraint() -> None:
    report = make_report(
        dependencies=(make_dependency("flask", None, constraint=">=2.0,<3.0"),)
    )
    entry = json.loads(render(report, OutputFormat.JSON))["dependencies"][0]
    assert entry["constraint"] == ">=2.0,<3.0"
    assert entry["package"]["version"] is None


def test_json_is_valid_when_empty() -> None:
    assert json.loads(render(make_report(), OutputFormat.JSON))["findings"] == []


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def rows(report_kwargs: dict[str, object]) -> list[dict[str, str]]:
    text = render(make_report(**report_kwargs), OutputFormat.CSV)
    return list(csv.DictReader(StringIO(text)))


def test_csv_always_writes_a_header() -> None:
    """An empty file and a failed run look identical; only one of those is fine."""
    text = render(make_report(), OutputFormat.CSV)
    assert text.startswith("severity,cvss_score,advisory_id")


def test_csv_one_row_per_finding_per_introducer() -> None:
    dep_a = make_dependency("requests", path="a/requirements.txt")
    dep_b = make_dependency("requests", path="b/requirements.txt")
    result = rows(
        {
            "vulnerabilities_checked": True,
            "findings": (
                Finding(
                    package=dep_a.ref,
                    advisory=make_advisory(),
                    fixed_version="2.32.0",
                    introduced_by=(dep_a, dep_b),
                ),
            ),
        }
    )
    assert [row["source_file"] for row in result] == [
        "a/requirements.txt",
        "b/requirements.txt",
    ]
    assert {row["package"] for row in result} == {"requests"}


def test_csv_carries_severity_and_purl() -> None:
    row = rows({"vulnerabilities_checked": True, "findings": (finding(),)})[0]
    assert row["severity"] == "high"
    assert row["cvss_score"] == "7.5"
    assert row["cve"] == "CVE-2024-0001"
    assert row["purl"] == "pkg:pypi/requests@2.31.0"


def test_csv_neutralises_a_formula_in_an_advisory_summary() -> None:
    """CSV is opened in spreadsheets, and summaries come from OSV.

    A summary beginning with ``=`` is a live formula the moment someone double-clicks
    the report, so it is written as text instead.
    """
    dep = make_dependency("requests")
    row = rows(
        {
            "vulnerabilities_checked": True,
            "findings": (
                Finding(
                    package=dep.ref,
                    advisory=make_advisory(summary='=HYPERLINK("http://evil","click")'),
                    introduced_by=(dep,),
                ),
            ),
        }
    )[0]
    assert row["summary"].startswith("'=")


def test_csv_neutralises_a_formula_in_a_package_name() -> None:
    """Package names and paths come out of the repository being scanned."""
    dep = make_dependency("@SUM(1+1)", path="-cmd|calc")
    row = rows(
        {
            "vulnerabilities_checked": True,
            "findings": (
                Finding(
                    package=dep.ref, advisory=make_advisory(), introduced_by=(dep,)
                ),
            ),
        }
    )[0]
    assert row["package"].startswith("'@")
    assert row["source_file"].startswith("'-")


def test_csv_leaves_ordinary_values_untouched() -> None:
    row = rows({"vulnerabilities_checked": True, "findings": (finding(),)})[0]
    assert row["summary"] == "Example vulnerability"
    assert row["package"] == "requests"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", list(OutputFormat))
def test_every_declared_format_renders(fmt: OutputFormat) -> None:
    """A format the CLI offers must produce output, not an error."""
    assert render(make_report(), fmt, color=False)


def test_an_unregistered_format_fails_clearly() -> None:
    with pytest.raises(IcebergSCAError, match="not implemented yet"):
        render(make_report(), "yaml")  # type: ignore[arg-type]


def test_the_approximate_marker_is_explained_rather_than_left_bare() -> None:
    """A lone ``~`` reads as either "incomplete" or "untrusted"; say which."""
    output = table_of(
        {
            "manifests": (
                ManifestResult(
                    ecosystem=EcosystemId.MAVEN,
                    directory=Path("."),
                    manifests=(Path("pom.xml"),),
                    parsed=(Path("pom.xml"),),
                    approximate=True,
                ),
            )
        }
    )
    assert "reconstructed" in output


def test_no_legend_when_nothing_was_reconstructed() -> None:
    output = table_of(
        {
            "manifests": (
                ManifestResult(
                    ecosystem=EcosystemId.PYPI,
                    directory=Path("."),
                    lockfiles=(Path("uv.lock"),),
                    parsed=(Path("uv.lock"),),
                    from_lockfile=True,
                ),
            )
        }
    )
    assert "reconstructed" not in output


def test_json_records_what_a_dependency_excludes() -> None:
    """An exclusion removes a package, so the report has to say it did."""
    report = make_report(
        dependencies=(
            make_dependency(
                "displaytag:displaytag",
                "1.2",
                ecosystem=EcosystemId.MAVEN,
                path="pom.xml",
                exclusions=frozenset({"com.lowagie:itext"}),
            ),
        )
    )
    payload = json.loads(render(report, OutputFormat.JSON))
    assert payload["dependencies"][0]["exclusions"] == ["com.lowagie:itext"]
