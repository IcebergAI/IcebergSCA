"""End-to-end CLI behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from icebergsca.cache import Cache
from icebergsca.cli.main import ExitCode, app
from icebergsca.core.errors import CacheError

runner = CliRunner()


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
    assert json.loads(destination.read_text())["schema_version"] == "1.0"


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


def test_scope_flag_is_repeatable_as_well_as_comma_separated(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["httpx>=0.27"]\n\n'
        '[project.optional-dependencies]\ndev = ["ruff>=0.9"]\n'
    )
    argv = ["scan", str(tmp_path), "--format", "json"]
    repeated = runner.invoke(app, [*argv, "--scope", "runtime", "--scope", "dev"])
    comma = runner.invoke(app, [*argv, "--scope", "runtime,dev"])
    for result in (repeated, comma):
        names = {
            e["package"]["name"] for e in json.loads(result.stdout)["dependencies"]
        }
        assert names == {"httpx", "ruff"}


def test_enum_choices_are_listed_in_help() -> None:
    """A bare ``<str>`` metavar tells a reader nothing about what is accepted."""
    # Wide enough that Rich does not wrap the metavar column mid-value.
    result = runner.invoke(app, ["scan", "--help"], env={"COLUMNS": "200"})
    assert "<pypi|npm|maven|go|cargo|nuget|rubygems>" in result.stdout
    assert "<runtime|dev|test|build|optional>" in result.stdout


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
