"""The bundled agent skill.

IcebergSCA ships a skill for consuming agents under ``icebergsca/.agents/skills/``,
following the convention fastapi, typer and sqlmodel use. These tests guard the two
ways it could silently break: the file moving, and packaging dropping the
dot-directory from the wheel. Either failure is invisible at runtime — the tool keeps
working, agents just stop finding the guidance.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

import icebergsca

SKILL_ROOT = Path(icebergsca.__file__).parent / ".agents" / "skills" / "icebergsca"
SKILL = SKILL_ROOT / "SKILL.md"

#: Claude Code truncates longer descriptions when deciding whether a skill applies.
_MAX_DESCRIPTION = 1024


def frontmatter() -> dict[str, str]:
    """Parse the YAML frontmatter without needing a YAML dependency at test time."""
    text = SKILL.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must open with YAML frontmatter"

    fields: dict[str, str] = {}
    key = None
    for line in match.group(1).splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
        elif key:
            fields[key] += " " + line.strip()
    return fields


# ---------------------------------------------------------------------------
# Location and packaging
# ---------------------------------------------------------------------------


def test_skill_lives_where_agents_look_for_it() -> None:
    """``<package>/.agents/skills/<name>/SKILL.md`` — the convention agents glob for."""
    assert SKILL.is_file()


def test_skill_is_importable_from_the_installed_package() -> None:
    """Resolving through ``icebergsca.__file__`` is how a consumer finds it."""
    assert SKILL_ROOT.parent.parent.name == ".agents"
    assert SKILL_ROOT.name == "icebergsca"


def test_reference_files_exist() -> None:
    references = {p.name for p in (SKILL_ROOT / "references").glob("*.md")}
    assert references == {"json-report.md", "ci-integration.md"}


def test_every_reference_link_resolves() -> None:
    """A dead link sends an agent looking for guidance that is not there."""
    text = SKILL.read_text(encoding="utf-8")
    for target in re.findall(r"\]\((references/[^)]+)\)", text):
        assert (SKILL_ROOT / target).is_file(), f"broken link: {target}"


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------


def test_frontmatter_has_the_required_fields() -> None:
    fields = frontmatter()
    assert fields["name"] == "icebergsca"
    assert fields["description"]


def test_description_is_within_the_length_agents_read() -> None:
    assert len(frontmatter()["description"]) <= _MAX_DESCRIPTION


def test_description_says_when_to_use_the_skill() -> None:
    """Selection is made from the description alone, so it must state its triggers."""
    assert "use when" in frontmatter()["description"].lower()


def test_skill_name_matches_the_distribution() -> None:
    pyproject = tomllib.loads(
        (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert frontmatter()["name"] == pyproject["project"]["name"]


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claim",
    [
        "vulnerabilities_checked",
        "unchecked_packages",
        "--format json",
        # An accepted finding read as a fixed one is the second way to produce a
        # false clean, so it belongs in the same guard as the first.
        "suppressed",
    ],
)
def test_skill_teaches_the_false_clean_checks(claim: str) -> None:
    """The one thing a consuming agent must not get wrong.

    An agent that reports "no vulnerabilities" from an empty findings array defeats
    the entire design of this tool, so the skill has to name the fields that prevent
    it — in the main file, not buried in a reference.
    """
    assert claim in SKILL.read_text(encoding="utf-8")


def test_skill_documents_the_exit_code_contract() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "Findings deliberately never change the exit code" in text


def test_skill_documents_the_pin_states() -> None:
    text = SKILL.read_text(encoding="utf-8")
    for pin in ("pinned", "resolved", "unresolved"):
        assert pin in text


def test_json_reference_covers_every_top_level_report_key() -> None:
    """A field the reference omits is one an agent will misread or ignore."""
    from icebergsca.report.json_ import to_dict
    from tests.conftest import make_report

    reference = (SKILL_ROOT / "references" / "json-report.md").read_text(
        encoding="utf-8"
    )
    for key in to_dict(make_report()):
        assert key in reference, f"json-report.md does not document '{key}'"
