"""End-to-end CLI behaviour."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from icebergsca.cache import Cache
from icebergsca.cli.main import ExitCode, app
from icebergsca.core.errors import CacheError

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(text: str) -> str:
    """Strip the styling Rich applies when it thinks it is writing to a terminal.

    Rich treats CI as a terminal, so help output is bare locally but styled under
    GitHub Actions — and it styles each choice in a metavar separately, which puts
    escape codes between every value. Anything asserting on rendered help has to
    strip them or it passes only off CI.
    """
    return _ANSI.sub("", text)


def project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0\n")
    return tmp_path


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == ExitCode.OK
    assert result.stdout.startswith("icebergsca ")


def test_scan_succeeds_on_a_simple_project(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(project(tmp_path))])
    assert result.exit_code == ExitCode.OK
    assert "2 dependencies" in result.stdout


def test_json_output_is_parseable_stdout(tmp_path: Path) -> None:
    """``--format json | jq`` must work, so nothing else may reach stdout."""
    result = runner.invoke(app, ["scan", str(project(tmp_path)), "--format", "json"])
    assert result.exit_code == ExitCode.OK
    document = json.loads(result.stdout)
    assert [entry["package"]["name"] for entry in document["dependencies"]] == [
        "requests",
        "flask",
    ]


def test_output_file(tmp_path: Path) -> None:
    destination = tmp_path / "out" / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(project(tmp_path)),
            "--format",
            "json",
            "--output",
            str(destination),
        ],
    )
    assert result.exit_code == ExitCode.OK
    assert json.loads(destination.read_text())["schema_version"] == "1.1"


def test_dev_dependencies_are_excluded_by_default(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\n'
        'dependencies = ["httpx>=0.27"]\n\n'
        '[project.optional-dependencies]\ndev = ["ruff>=0.9"]\n'
    )
    default = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    names = {e["package"]["name"] for e in json.loads(default.stdout)["dependencies"]}
    assert names == {"httpx"}

    with_dev = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--include-dev"]
    )
    names = {e["package"]["name"] for e in json.loads(with_dev.stdout)["dependencies"]}
    assert names == {"httpx", "ruff"}


def test_scope_flag_overrides_include_dev(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["httpx>=0.27"]\n\n'
        '[project.optional-dependencies]\ndev = ["ruff>=0.9"]\n'
    )
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--scope", "dev"]
    )
    names = {e["package"]["name"] for e in json.loads(result.stdout)["dependencies"]}
    assert names == {"ruff"}


def test_ecosystem_filter(tmp_path: Path) -> None:
    project(tmp_path)
    (tmp_path / "package.json").write_text("{}")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--ecosystem", "pypi"]
    )
    document = json.loads(result.stdout)
    assert {m["ecosystem"] for m in document["manifests"]} == {"PyPI"}


def test_scope_flag_is_repeatable(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["httpx>=0.27"]\n\n'
        '[project.optional-dependencies]\ndev = ["ruff>=0.9"]\n'
    )
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "json", "--scope", "runtime"]
        + ["--scope", "dev"],
    )
    names = {e["package"]["name"] for e in json.loads(result.stdout)["dependencies"]}
    assert names == {"httpx", "ruff"}


def test_enum_choices_are_listed_in_help() -> None:
    """A bare ``<str>`` metavar tells a reader nothing about what is accepted."""
    # Wide enough that Rich does not wrap the metavar column mid-value.
    result = runner.invoke(app, ["scan", "--help"], env={"COLUMNS": "200"})
    rendered = plain(result.stdout)
    assert "<pypi|npm|maven|go|cargo|nuget|rubygems>" in rendered
    assert "<runtime|dev|test|build|optional>" in rendered


def test_exclude_glob(tmp_path: Path) -> None:
    project(tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "requirements.txt").write_text("django==5.0\n")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--exclude", "sub"]
    )
    document = json.loads(result.stdout)
    assert len(document["manifests"]) == 1


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_missing_path_exits_scan_failed(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == ExitCode.SCAN_FAILED


def test_unknown_format_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(project(tmp_path)), "--format", "yaml"])
    assert result.exit_code == ExitCode.USAGE


def test_unknown_scope_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(project(tmp_path)), "--scope", "prod"])
    assert result.exit_code == ExitCode.USAGE


def test_sarif_output_is_valid_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(project(tmp_path)), "--format", "sarif"])
    assert result.exit_code == ExitCode.OK
    assert json.loads(result.stdout)["version"] == "2.1.0"


def test_sbom_command_emits_cyclonedx(tmp_path: Path) -> None:
    result = runner.invoke(app, ["sbom", str(project(tmp_path))])
    assert result.exit_code == ExitCode.OK
    document = json.loads(result.stdout)
    assert document["bomFormat"] == "CycloneDX"
    assert {c["name"] for c in document["components"]} == {"requests", "flask"}


def test_sbom_defaults_to_components_only(tmp_path: Path) -> None:
    """An inventory should not need to ask anyone about vulnerabilities."""
    result = runner.invoke(app, ["sbom", str(project(tmp_path))])
    document = json.loads(result.stdout)
    assert "vulnerabilities" not in document
    properties = {p["name"]: p["value"] for p in document["metadata"]["properties"]}
    assert properties["icebergsca:vulnerabilitiesChecked"] == "false"


def test_sbom_with_vulnerabilities_adds_the_vex_section(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["sbom", str(project(tmp_path)), "--with-vulnerabilities"]
    )
    assert "vulnerabilities" in json.loads(result.stdout)


def test_empty_directory_still_succeeds(tmp_path: Path) -> None:
    """Nothing to scan is not a failure — it is a finding about the project."""
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.OK
    assert "No dependency manifests" in result.stdout


def test_cache_commands_report_an_unusable_cache_as_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken cache is the whole subject of these commands, not a stack trace."""

    def refuse(path: Path | None = None) -> Cache:
        raise CacheError("could not open cache at /nowhere: permission denied")

    monkeypatch.setattr("icebergsca.cli.main.Cache.open", refuse)

    for command in (["cache", "clear"], ["cache", "prune"]):
        result = runner.invoke(app, command)
        assert result.exit_code == ExitCode.SCAN_FAILED
        assert result.exception is None or isinstance(result.exception, SystemExit)


def test_cache_commands_report_a_failing_query_as_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure part-way through must still be an error message, not a traceback.

    Both spellings exit 1 under the runner, so the assertion that matters is that no
    exception escaped and the user got told what went wrong.
    """

    def explode(self: Cache) -> int:
        raise CacheError("disk is full")

    monkeypatch.setattr(
        "icebergsca.cli.main.Cache.open", lambda path=None: Cache.memory()
    )
    monkeypatch.setattr(Cache, "clear", explode)

    result = runner.invoke(app, ["cache", "clear"])
    assert result.exit_code == ExitCode.SCAN_FAILED
    assert isinstance(result.exception, SystemExit)
    assert "disk is full" in result.stderr


# ---------------------------------------------------------------------------
# Suppression and --fail-on
# ---------------------------------------------------------------------------


class _FindingTransport(httpx.AsyncBaseTransport):
    """Answer OSV as though every queried package had one high-severity advisory."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            body = json.loads(request.content or b'{"queries": []}')
            results = [
                {"vulns": [{"id": "GHSA-test", "modified": "2026-01-01T00:00:00Z"}]}
                for _ in body.get("queries", [])
            ]
            return httpx.Response(200, json={"results": results}, request=request)
        if "/v1/vulns/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-test",
                    "modified": "2026-01-01T00:00:00Z",
                    "aliases": ["CVE-2026-9999"],
                    "summary": "Example",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        }
                    ],
                },
                request=request,
            )
        return httpx.Response(404, json={"error": "not mocked"}, request=request)


@pytest.fixture
def with_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    from icebergsca.core import scanner

    monkeypatch.setattr(
        scanner,
        "build_http_client",
        lambda options: httpx.AsyncClient(transport=_FindingTransport()),
    )


def one_package(tmp_path: Path) -> Path:
    """A project with a single dependency, so one ignore entry covers everything."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    return tmp_path


def ignore_file(tmp_path: Path, **fields: str) -> Path:
    entry = {
        "advisory": "GHSA-test",
        "package": "requests",
        "reason": "Assessed: not reachable from our entry points",
    } | fields
    body = "\n".join(f'{key} = "{value}"' for key, value in entry.items())
    target = tmp_path / ".icebergsca.toml"
    target.write_text(f"[[ignore]]\n{body}\n")
    return target


def test_findings_alone_still_exit_zero(tmp_path: Path, with_findings: None) -> None:
    """The design this feature must not undo: a finding is data, not a failure."""
    result = runner.invoke(app, ["scan", str(project(tmp_path))])
    assert result.exit_code == ExitCode.OK


def test_fail_on_exits_three_above_the_threshold(
    tmp_path: Path, with_findings: None
) -> None:
    result = runner.invoke(app, ["scan", str(project(tmp_path)), "--fail-on", "high"])
    assert result.exit_code == ExitCode.FINDINGS


def test_fail_on_exits_zero_below_the_threshold(
    tmp_path: Path, with_findings: None
) -> None:
    result = runner.invoke(
        app, ["scan", str(project(tmp_path)), "--fail-on", "critical"]
    )
    assert result.exit_code == ExitCode.OK


def test_an_accepted_finding_does_not_trip_the_gate(
    tmp_path: Path, with_findings: None
) -> None:
    """The whole point of pairing the two: gating is only safe once you can accept."""
    target = one_package(tmp_path)
    ignore_file(target)
    result = runner.invoke(app, ["scan", str(target), "--fail-on", "high"])
    assert result.exit_code == ExitCode.OK


def test_an_expired_entry_trips_the_gate_again(
    tmp_path: Path, with_findings: None
) -> None:
    target = one_package(tmp_path)
    ignore_file(target, expires="2020-01-01")
    result = runner.invoke(app, ["scan", str(target), "--fail-on", "high"])
    assert result.exit_code == ExitCode.FINDINGS


def test_an_incomplete_scan_exits_one_not_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The false-clean trap, from the other side.

    Completeness is checked before the gate, so a scan that could not look anything up
    fails as a broken scan — never passing because it happened to find nothing, and
    never reported as a policy failure it did not actually establish.
    """
    from icebergsca.core import scanner
    from icebergsca.osv import client as client_module

    # Same collapse as tests/test_osv.py: the retry schedule is asserted there, and
    # paying it in real seconds here would put the suite over its time budget.
    monkeypatch.setattr(client_module, "_BACKOFF_BASE", 0.0001)
    monkeypatch.setattr(client_module, "_BACKOFF_CAP", 0.001)

    class _Unreachable(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(
        scanner,
        "build_http_client",
        lambda options: httpx.AsyncClient(transport=_Unreachable()),
    )
    result = runner.invoke(
        app, ["scan", str(project(tmp_path)), "--fail-on", "critical"]
    )
    assert result.exit_code == ExitCode.SCAN_FAILED


def test_a_suppressed_finding_is_still_reported(
    tmp_path: Path, with_findings: None
) -> None:
    target = one_package(tmp_path)
    ignore_file(target)
    result = runner.invoke(app, ["scan", str(target), "--format", "json"])
    document = json.loads(result.stdout)

    assert document["summary"]["suppressed"] == 1
    assert any(f["suppression"] for f in document["findings"])


def test_an_unreadable_ignore_file_named_explicitly_is_an_error(
    tmp_path: Path,
) -> None:
    """Asking for a file by name and silently getting no rules is the wrong surprise."""
    result = runner.invoke(
        app,
        ["scan", str(project(tmp_path)), "--ignore-file", str(tmp_path / "nope.toml")],
    )
    assert result.exit_code == ExitCode.SCAN_FAILED
    assert "not found" in result.stderr


def test_a_malformed_ignore_file_fails_loudly(tmp_path: Path) -> None:
    target = project(tmp_path)
    (target / ".icebergsca.toml").write_text('[[ignore]]\nadvisroy = "x"\n')
    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == ExitCode.SCAN_FAILED
    assert "advisroy" in result.stderr


def test_unknown_fail_on_severity_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(project(tmp_path)), "--fail-on", "catastrophic"]
    )
    assert result.exit_code == ExitCode.USAGE


def test_fail_on_choices_are_listed_in_help() -> None:
    result = runner.invoke(app, ["scan", "--help"], env={"COLUMNS": "200"})
    assert "critical|high|medium|low|none|unknown" in plain(result.stdout)
