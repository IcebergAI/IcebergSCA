---
title: For AI agents
icon: material/robot-outline
---

# For AI agents

IcebergSCA ships an agent skill **inside the wheel**, following the same
convention FastAPI, Typer and SQLModel use:

```
icebergsca/.agents/skills/icebergsca/SKILL.md
                                    /references/json-report.md
                                    /references/ci-integration.md
```

Agents that glob site-packages for `SKILL.md` find it automatically after
install — no configuration, no separate download, and the version installed is
always the version documented.

- [`SKILL.md`](https://github.com/IcebergAI/IcebergSCA/blob/main/src/icebergsca/.agents/skills/icebergsca/SKILL.md)
  — invocation, output interpretation, exit codes, scope and network behaviour
- [`references/json-report.md`](https://github.com/IcebergAI/IcebergSCA/blob/main/src/icebergsca/.agents/skills/icebergsca/references/json-report.md)
  — every field of the JSON document
- [`references/ci-integration.md`](https://github.com/IcebergAI/IcebergSCA/blob/main/src/icebergsca/.agents/skills/icebergsca/references/ci-integration.md)
  — SARIF, SBOM artefacts, gating and caching

## Before reporting a project clean

An empty `findings` array means "checked and clean", "never checked" or
"partially checked" — and only the report can say which. The skill exists mostly
to stop an agent collapsing those three into a reassuring sentence.

Three fields decide it:

```bash
icebergsca scan . --format json | jq '{
  checked:   .scan.vulnerabilities_checked,
  complete:  .scan.complete,
  unchecked: .summary.unchecked_packages,
  findings:  .summary.findings
}'
```

| Field | Meaning if wrong |
|---|---|
| `scan.vulnerabilities_checked` | `false` means the OSV lookup never ran. No conclusion can be drawn at all |
| `summary.unchecked_packages` | Above `0` means some packages could not be looked up. The result is partial |
| `scan.complete` | `false` means either of the above, or a file failed to parse |

A correct summary:

```python
report = json.loads(output)

if not report["scan"]["vulnerabilities_checked"]:
    verdict = "Not checked — the vulnerability lookup did not run."
elif report["summary"]["unchecked_packages"]:
    n = report["summary"]["unchecked_packages"]
    verdict = f"Incomplete — {n} package(s) could not be checked. Findings so far: ..."
elif not report["summary"]["findings"]:
    verdict = f"No known vulnerabilities in {report['summary']['packages']} packages."
else:
    verdict = f"{report['summary']['findings']} finding(s): {report['summary']['by_severity']}"
```

```python
# DO NOT DO THIS: an empty list is not evidence of safety.
if not report["findings"]:
    print("No vulnerabilities found")
```

## Other rules the skill enforces

- **Always `--format json`.** The table layout is for humans and is not a stable
  interface; `grep`-ing it will break.
- **Quote the CVE, not OSV's ID.** `advisory.aliases` carries the identifier a
  user can look up anywhere. `advisory.id` is OSV's own.
- **`fixed_version: null` means no fix is known.** Say so, rather than inventing
  an upgrade.
- **`severity.level: "unknown"` is not `"none"`.** Unknown means nobody scored
  it, not that it is harmless.
- **Say when a finding is `resolved` or `unresolved`.** A user running an older
  lockfile may have a different version than the one scanned.
- **`introduced_by` names the file to edit.** Use it instead of making the user
  hunt for where a transitive dependency came from.
- **Escalate `malicious: true`.** An OSV `MAL-` advisory is a package published
  to attack its consumers, not a bug. The remediation is removal, not upgrade.

## How the skill is kept current

The skill is tested, not just written: `tests/test_skill.py` guards its
location, frontmatter and links, and asserts that
`references/json-report.md` documents **every** top-level key the JSON renderer
emits. CI separately asserts that the dot-directory survives packaging, because
if it ever stopped being bundled the tool would keep working while consuming
agents silently lost their guidance.

A skill describing flags that no longer exist is worse than no skill at all.
