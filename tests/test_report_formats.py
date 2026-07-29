"""SARIF and CycloneDX output, validated against the published schemas.

The schemas under ``tests/schemas`` are the official ones, vendored so the suite
never needs the network. Hand-writing these documents is only defensible because
this test proves the result is actually valid.
"""

from __future__ import annotations

import json
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft4Validator, Draft7Validator
from referencing import Registry
from referencing.jsonschema import DRAFT7

from icebergsca.core.models import (
    EcosystemId,
    Finding,
    PackageRef,
    Severity,
    SeverityLevel,
    Suppression,
)
from icebergsca.report import OutputFormat, cyclonedx, render, sarif
from tests.conftest import make_advisory, make_dependency, make_report

SCHEMAS = Path(__file__).parent / "schemas"


@cache
def _schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def _report(errors: list[Any]) -> str:
    return "\n".join(
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: "
        f"{error.message}"
        for error in errors[:5]
    )


def validate_cyclonedx(document: dict[str, Any]) -> None:
    """Validate against CycloneDX 1.6.

    The spec splits across three files; the two siblings are registered under the
    relative names ``bom-1.6.schema.json`` refers to, so resolution stays offline.
    """
    registry = Registry().with_resources(
        [
            (name, DRAFT7.create_resource(_schema(name)))
            for name in ("spdx.schema.json", "jsf-0.82.schema.json")
        ]
    )
    validator = Draft7Validator(_schema("bom-1.6.schema.json"), registry=registry)
    errors = sorted(
        validator.iter_errors(document), key=lambda e: list(e.absolute_path)
    )
    assert not errors, _report(errors)


def validate_sarif(document: dict[str, Any]) -> None:
    """Validate against SARIF 2.1.0, which is published as draft-04."""
    validator = Draft4Validator(_schema("sarif-2.1.0.schema.json"))
    errors = sorted(
        validator.iter_errors(document), key=lambda e: list(e.absolute_path)
    )
    assert not errors, _report(errors)


def sample_report(**overrides: Any) -> Any:
    """A report exercising every branch the renderers have."""
    scored = make_dependency("requests", "2.19.1", path="requirements.txt", line=3)
    transitive = make_dependency(
        "urllib3", "1.24.1", direct=False, path="requirements.txt", line=None
    )
    unscored = make_dependency(
        "left-pad", "1.0.0", ecosystem=EcosystemId.NPM, path="package.json"
    )
    accepted = make_dependency("jinja2", "3.1.2", path="requirements.txt", line=7)

    findings = (
        Finding(
            package=scored.ref,
            advisory=make_advisory(
                "GHSA-aaaa", level=SeverityLevel.CRITICAL, score=9.8
            ),
            fixed_version="2.20.0",
            introduced_by=(scored,),
        ),
        Finding(
            package=transitive.ref,
            advisory=make_advisory(
                "GHSA-bbbb", level=SeverityLevel.MEDIUM, score=5.3, aliases=()
            ),
            fixed_version=None,
            introduced_by=(transitive,),
        ),
        Finding(
            package=unscored.ref,
            # No severity at all: the renderers must still produce valid documents.
            advisory=make_advisory("MAL-2024-1", level=None),
            introduced_by=(unscored,),
        ),
        Finding(
            package=accepted.ref,
            advisory=make_advisory("GHSA-cccc", level=SeverityLevel.HIGH, score=7.5),
            introduced_by=(accepted,),
            # Suppressed findings are rendered, not dropped, so they must satisfy the
            # official schemas like any other — which is what this entry buys.
            suppression=Suppression(
                reason="Unreachable: the affected parser is never called",
                expires=date(2026, 10, 27),
                rule="GHSA-cccc@jinja2",
            ),
        ),
    )

    defaults: dict[str, Any] = {
        "dependencies": (scored, transitive, unscored, accepted),
        "findings": findings,
        "vulnerabilities_checked": True,
        "warnings": ("an example warning",),
    }
    return make_report(**{**defaults, **overrides})


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_validates_against_the_official_schema() -> None:
    validate_sarif(sarif.to_dict(sample_report()))


def test_sarif_validates_when_empty() -> None:
    validate_sarif(sarif.to_dict(make_report(vulnerabilities_checked=True)))


def test_sarif_severity_is_numeric_for_github() -> None:
    """GitHub reads security-severity, not level, to rank an alert."""
    document = sarif.to_dict(sample_report())
    rules = {
        rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]
    }
    assert rules["GHSA-aaaa"]["properties"]["security-severity"] == "9.8"


def test_sarif_unscored_advisory_still_gets_a_severity_number() -> None:
    """Omitting it would make a malicious-package alert render as a plain warning."""
    document = sarif.to_dict(sample_report())
    rules = {
        rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]
    }
    assert float(rules["MAL-2024-1"]["properties"]["security-severity"]) >= 9.0


def test_sarif_high_and_above_are_errors() -> None:
    document = sarif.to_dict(sample_report())
    levels = {
        result["ruleId"]: result["level"] for result in document["runs"][0]["results"]
    }
    assert levels["GHSA-aaaa"] == "error"
    assert levels["GHSA-bbbb"] == "warning"


def result_for(document: dict[str, Any], rule_id: str) -> dict[str, Any]:
    return next(r for r in document["runs"][0]["results"] if r["ruleId"] == rule_id)


def test_sarif_fingerprints_do_not_depend_on_line_numbers() -> None:
    """Reformatting a manifest must not close every alert and reopen it as new."""
    first = sarif.to_dict(sample_report())

    moved = make_dependency("requests", "2.19.1", path="requirements.txt", line=999)
    second = sarif.to_dict(
        sample_report(
            findings=(
                Finding(
                    package=moved.ref,
                    advisory=make_advisory("GHSA-aaaa", level=SeverityLevel.CRITICAL),
                    introduced_by=(moved,),
                ),
            )
        )
    )

    assert (
        result_for(first, "GHSA-aaaa")["partialFingerprints"]
        == result_for(second, "GHSA-aaaa")["partialFingerprints"]
    )


def test_sarif_anchors_to_the_manifest_line_when_known() -> None:
    document = sarif.to_dict(sample_report())
    location = result_for(document, "GHSA-aaaa")["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "requirements.txt"
    assert location["region"]["startLine"] == 3


def test_sarif_omits_the_region_when_the_line_is_unknown() -> None:
    """A guessed line number is worse than none — it points at the wrong code."""
    transitive = result_for(sarif.to_dict(sample_report()), "GHSA-bbbb")
    assert "region" not in transitive["locations"][0]["physicalLocation"]


def test_sarif_records_an_incomplete_scan_in_the_invocation() -> None:
    document = sarif.to_dict(sample_report())
    invocation = document["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["toolExecutionNotifications"][0]["message"]["text"]


def test_sarif_marks_an_unchecked_scan_unsuccessful() -> None:
    document = sarif.to_dict(make_report())
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_sarif_renders_through_the_format_dispatcher() -> None:
    text = render(sample_report(), OutputFormat.SARIF)
    validate_sarif(json.loads(text))


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------


def test_cyclonedx_validates_against_the_official_schema() -> None:
    validate_cyclonedx(cyclonedx.to_dict(sample_report()))


def test_cyclonedx_validates_when_empty() -> None:
    validate_cyclonedx(cyclonedx.to_dict(make_report()))


def test_cyclonedx_components_carry_purls() -> None:
    document = cyclonedx.to_dict(sample_report())
    purls = {component["purl"] for component in document["components"]}
    assert "pkg:pypi/requests@2.19.1" in purls
    assert "pkg:npm/left-pad@1.0.0" in purls


def test_cyclonedx_vulnerabilities_affect_their_component() -> None:
    document = cyclonedx.to_dict(sample_report())
    entry = next(v for v in document["vulnerabilities"] if v["id"] == "GHSA-aaaa")
    assert entry["affects"][0]["ref"] == "pkg:pypi/requests@2.19.1"
    assert entry["ratings"][0]["severity"] == "critical"
    assert entry["recommendation"].startswith("Upgrade requests to 2.20.0")


def test_cyclonedx_unscored_rating_uses_the_other_method() -> None:
    """Claiming a CVSS method for a rating that has no vector would be a fabrication."""
    document = cyclonedx.to_dict(sample_report())
    entry = next(v for v in document["vulnerabilities"] if v["id"] == "MAL-2024-1")
    assert entry["ratings"][0]["method"] == "other"
    assert "score" not in entry["ratings"][0]


def test_cyclonedx_components_only_omits_vulnerabilities_entirely() -> None:
    document = cyclonedx.to_dict(sample_report(), include_vulnerabilities=False)
    assert "vulnerabilities" not in document
    assert document["components"]


def test_cyclonedx_records_whether_vulnerabilities_were_checked() -> None:
    """An empty vulnerabilities array cannot distinguish "clean" from "not asked"."""
    properties = {
        entry["name"]: entry["value"]
        for entry in cyclonedx.to_dict(make_report())["metadata"]["properties"]
    }
    assert properties["icebergsca:vulnerabilitiesChecked"] == "false"


def test_cyclonedx_dependency_graph_links_direct_deps_to_the_root() -> None:
    document = cyclonedx.to_dict(sample_report())
    graph = {entry["ref"]: entry["dependsOn"] for entry in document["dependencies"]}
    assert "pkg:pypi/requests@2.19.1" in graph["root"]
    # A transitive dependency is not a child of the root component.
    assert "pkg:pypi/urllib3@1.24.1" not in graph["root"]


def test_cyclonedx_dependency_graph_uses_recorded_parents() -> None:
    parent = make_dependency("express", "4.19.2", ecosystem=EcosystemId.NPM)
    child = make_dependency("ms", "2.0.0", ecosystem=EcosystemId.NPM, direct=False)
    child = (
        type(child)(**{**child.__dict__, "parents": (parent.ref,)}) if False else child
    )
    document = cyclonedx.to_dict(make_report(dependencies=(parent, child)))
    graph = {entry["ref"]: entry["dependsOn"] for entry in document["dependencies"]}
    assert "pkg:npm/express@4.19.2" in graph["root"]
    assert "pkg:npm/ms@2.0.0" in graph


def test_cyclonedx_component_properties_state_pin_and_scope() -> None:
    document = cyclonedx.to_dict(sample_report())
    component = next(
        c for c in document["components"] if c["purl"] == "pkg:pypi/requests@2.19.1"
    )
    properties = {entry["name"]: entry["value"] for entry in component["properties"]}
    assert properties["icebergsca:pin"] == "pinned"
    assert properties["icebergsca:direct"] == "true"


def test_cyclonedx_renders_through_the_format_dispatcher() -> None:
    validate_cyclonedx(json.loads(render(sample_report(), OutputFormat.CYCLONEDX)))


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (SeverityLevel.CRITICAL, "critical"),
        (SeverityLevel.HIGH, "high"),
        (SeverityLevel.MEDIUM, "medium"),
        (SeverityLevel.LOW, "low"),
    ],
)
def test_cyclonedx_severity_vocabulary(level: SeverityLevel, expected: str) -> None:
    dep = make_dependency()
    report = make_report(
        vulnerabilities_checked=True,
        dependencies=(dep,),
        findings=(
            Finding(
                package=dep.ref,
                advisory=make_advisory(level=level),
                introduced_by=(dep,),
            ),
        ),
    )
    document = cyclonedx.to_dict(report)
    assert document["vulnerabilities"][0]["ratings"][0]["severity"] == expected
    validate_cyclonedx(document)


def test_cyclonedx_handles_a_package_with_no_version() -> None:
    """An unresolved constraint still produces a valid component entry."""
    dep = make_dependency("flask", None)
    document = cyclonedx.to_dict(make_report(dependencies=(dep,)))
    assert "version" not in document["components"][0]
    validate_cyclonedx(document)


def test_severity_is_carried_through_from_a_vector() -> None:
    severity = Severity(SeverityLevel.HIGH, 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N")
    dep = make_dependency()
    finding = Finding(
        package=PackageRef(EcosystemId.PYPI, "requests", "2.31.0"),
        advisory=make_advisory().__class__(
            id="GHSA-x", modified="2026-01-01", severity=severity
        ),
        introduced_by=(dep,),
    )
    document = cyclonedx.to_dict(
        make_report(
            vulnerabilities_checked=True, dependencies=(dep,), findings=(finding,)
        )
    )
    rating = document["vulnerabilities"][0]["ratings"][0]
    assert rating["method"] == "CVSSv31"
    assert rating["score"] == 7.5


def test_sarif_marks_a_suppressed_result_rather_than_dropping_it() -> None:
    """Dropped, GitHub would close the alert as fixed. Marked, it shows as dismissed."""
    document = sarif.to_dict(sample_report())
    result = result_for(document, "GHSA-cccc")
    assert result["suppressions"] == [
        {
            "kind": "external",
            "status": "accepted",
            "justification": "Unreachable: the affected parser is never called",
        }
    ]


def test_sarif_omits_suppressions_entirely_when_nothing_was_accepted() -> None:
    assert "suppressions" not in result_for(sarif.to_dict(sample_report()), "GHSA-aaaa")


def test_cyclonedx_records_an_accepted_finding_without_claiming_it_is_unaffected() -> (
    None
):
    """``state`` is a closed enum of security claims we cannot make from free text."""
    document = cyclonedx.to_dict(sample_report(), include_vulnerabilities=True)
    entry = next(v for v in document["vulnerabilities"] if v["id"] == "GHSA-cccc")
    assert "Unreachable" in entry["analysis"]["detail"]
    assert "state" not in entry["analysis"]

    properties = {p["name"]: p["value"] for p in document["metadata"]["properties"]}
    assert properties["icebergsca:suppressedCount"] == "1"
