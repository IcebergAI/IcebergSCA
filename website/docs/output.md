---
title: Output and CI
icon: material/export-variant
---

# Output and CI

Report output goes to **stdout** and logs go to **stderr**, so `--format json |
jq` is always clean. `--output <path>` writes to a file instead.

| `--format` | Use |
|---|---|
| `table` | Human-readable terminal output (default) |
| `json` | Full-fidelity document — every dependency, finding, source and warning |
| `csv` | One row per finding per introducing manifest, for spreadsheets |
| `sarif` | SARIF 2.1.0 for GitHub code scanning, with stable fingerprints |
| `cyclonedx` | CycloneDX 1.6 — an SBOM and VEX document in one file |

Every format is a projection of the JSON document. SARIF and CycloneDX are
validated against the official published schemas in the test suite.

## JSON

The canonical output. Shape is versioned by `schema_version`.

```bash
icebergsca scan . --format json --output report.json
```

```json
{
  "schema_version": "1.0",
  "tool": { "name": "icebergsca", "version": "0.1.0" },
  "scan": { "root": "...", "status": "ok",
            "vulnerabilities_checked": true, "complete": true },
  "summary": { "dependencies": 21, "packages": 21, "findings": 12,
               "by_severity": { "critical": 3, "high": 4, "medium": 4, "low": 1 },
               "unchecked_packages": 0, "skipped_files": 0 },
  "manifests": [ ... ],
  "dependencies": [ ... ],
  "findings": [ ... ],
  "unchecked_packages": [ ... ],
  "skipped": [ ... ],
  "warnings": [ ... ]
}
```

Three things are easy to get wrong:

- **`status: "ok"` is about the scan, not the findings.** A scan that finds
  forty critical vulnerabilities still completed successfully.
- **`summary.dependencies` counts provenance duplicates**; a package declared in
  two manifests appears twice. Use `summary.packages` when reporting "we checked
  N packages".
- **`manifests[].parsed` is what was actually read**, which differs from
  `lockfiles` when a lockfile could not be parsed and its manifest was used
  instead.
- **`dependencies[].exclusions` explains an absence.** A coordinate listed there
  was removed from the graph on purpose, which is the one case where something
  missing is not something overlooked.

The last three arrays — `unchecked_packages`, `skipped` and `warnings` — are the
report's account of what it could not do. They are the difference between
"clean" and "we did not look", so never drop them when summarising.

The complete field reference ships with the package, in
[`references/json-report.md`](agents.md).

## SARIF and GitHub code scanning

```yaml
- run: >-
    uvx --from git+https://github.com/IcebergAI/IcebergSCA@v0.1.0
    icebergsca scan . --format sarif --output icebergsca.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: icebergsca.sarif
    category: icebergsca
```

The job needs `security-events: write`.

- `partialFingerprints` are derived from the package URL and advisory ID, never
  a line number — so reformatting a manifest does not close every alert and
  immediately reopen it as new.
- `security-severity` carries the numeric CVSS score, which is what GitHub ranks
  on. Advisories with no vector get a representative score for their band, so a
  malicious-package alert is never rendered as a plain warning.
- `high` and `critical` map to SARIF `error`, so they cannot be filtered away as
  warnings.
- Warnings from an incomplete scan ride along in
  `runs[].invocations[].toolExecutionNotifications`, and `executionSuccessful`
  is `false` when the scan did not complete.

## CycloneDX and SBOMs

```bash
icebergsca sbom ./myproject                          # CycloneDX 1.6, components only
icebergsca sbom ./myproject --with-vulnerabilities   # ...plus a VEX section
```

`sbom` is `scan --format cyclonedx` with a different default: components only,
and no network calls to OSV at all. `metadata.properties` carries
`icebergsca:vulnerabilitiesChecked`, and the same rule applies as everywhere
else — a components-only SBOM is an inventory, not an assessment. Do not publish
one as evidence that anything was checked.

## Exit codes

| Exit code | Meaning | Pipeline response |
|---|---|---|
| `0` | Scan completed. Vulnerabilities may have been found — that is not an error | Read `summary.findings` to decide what to do |
| `1` | Scan failed, or completed only partially — some files or packages went unchecked | Fail the job; the result is not trustworthy |
| `2` | Usage error: bad flag, unknown format (Click's reserved code) | Fix the invocation |

Findings deliberately never change the exit code. A scanner that exits non-zero
on findings sooner or later gets `|| true` appended, at which point genuine tool
failures go unnoticed too.

!!! note "Exit 2 is usage, exit 1 is scan failure"

    The reverse of the original plan. Click reserves 2 for usage errors, and
    remapping it means overriding framework internals for nothing.

## Gating a build on severity

A built-in `--fail-on <severity>` is planned; the report model already carries
everything it needs. Until then, read the JSON — and check `scan.complete`
**first**, because gating on findings alone would pass a scan that failed to
check anything:

```bash
icebergsca scan . --format json --output report.json
jq -e '.scan.complete' report.json > /dev/null || { echo "scan incomplete"; exit 1; }
jq -e '(.summary.by_severity.critical // 0) == 0' report.json > /dev/null \
  || { echo "critical vulnerabilities found"; exit 1; }
```

## A full workflow

```yaml
name: Dependency scan

on:
  push: { branches: [main] }
  pull_request:
  schedule:
    - cron: "0 6 * * 1"   # advisories appear for code that has not changed

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v5
      - uses: astral-sh/setup-uv@v8

      - name: Scan
        run: >-
          uvx --from git+https://github.com/IcebergAI/IcebergSCA@v0.1.0
          icebergsca scan . --exclude 'tests/fixtures/**' --format sarif --output sca.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sca.sarif
          category: icebergsca
```

The scheduled run matters: most new findings arrive because an advisory was
published, not because the code changed.

Deliberately vulnerable test fixtures are a common source of noise — exclude
them rather than explaining them away.

### Caching between runs

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/icebergsca
    key: icebergsca-${{ hashFiles('**/uv.lock', '**/package-lock.json') }}
    restore-keys: icebergsca-
```

Advisory detail is keyed by OSV's `modified` timestamp, so a cached advisory
cannot go stale — a revised one lands under a different key. Query results carry
a 24-hour TTL. Use `--offline` on air-gapped runners; it reports anything
uncached as unchecked rather than assuming it clean.

## Monorepos

One invocation covers every ecosystem and produces a single merged report,
grouped by manifest, with each finding carrying the files that introduced it:

```bash
icebergsca scan . --format json | jq -r '
  .findings[] | .introduced_by[] | .path' | sort | uniq -c | sort -rn
```

A per-file count is usually the fastest route to "which team owns this".
