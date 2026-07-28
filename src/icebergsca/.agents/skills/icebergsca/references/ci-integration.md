# CI integration

## Exit codes in a pipeline

Findings never change the exit code. A non-zero exit means the scan itself did not complete.

| Code | Meaning | Pipeline response |
|---|---|---|
| `0` | Scan completed | Read `summary.findings` to decide what to do |
| `1` | Scan failed or partial | Fail the job — the result is not trustworthy |
| `2` | Usage error | Fix the invocation |

This is deliberate: a scanner that exits non-zero on findings gets `|| true` appended within a
week, at which point genuine tool failures also go unnoticed.

To gate on severity today, read the JSON:

```bash
icebergsca scan . --format json --output report.json
jq -e '.scan.complete' report.json > /dev/null || { echo "scan incomplete"; exit 1; }
jq -e '(.summary.by_severity.critical // 0) == 0' report.json > /dev/null \
  || { echo "critical vulnerabilities found"; exit 1; }
```

Check `scan.complete` **first**. Gating on findings alone would pass a scan that failed to
check anything.

A built-in `--fail-on <severity>` flag is planned but not yet implemented.

## GitHub code scanning

```yaml
- name: Scan dependencies
  run: uvx icebergsca scan . --format sarif --output icebergsca.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: icebergsca.sarif
    category: icebergsca
```

The job needs `security-events: write` permission.

Notes on the SARIF we emit:

* `partialFingerprints` are derived from the package URL and advisory ID, never a line number,
  so reformatting a manifest does not close every alert and immediately reopen it as new.
* `security-severity` carries the numeric CVSS score. GitHub reads this rather than the SARIF
  `level` when ranking an alert; advisories with no vector get a representative score for their
  band so a malicious-package alert is never rendered as a plain warning.
* `high` and `critical` map to SARIF `error`, so they cannot be filtered out as warnings.
* Warnings from an incomplete scan ride along in `runs[].invocations[].toolExecutionNotifications`,
  and `executionSuccessful` is `false` when the scan did not complete.

## Full workflow

```yaml
name: Supply chain

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
        run: uvx icebergsca scan . --exclude 'tests/fixtures/**' --format sarif --output sca.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sca.sarif
          category: icebergsca
```

The scheduled run matters more than it looks: most new findings arrive because an advisory was
published, not because the code changed.

## SBOM artefacts

```yaml
- name: Generate SBOM
  run: uvx icebergsca sbom . --output sbom.cdx.json

- uses: actions/upload-artifact@v5
  with:
    name: sbom
    path: sbom.cdx.json
```

The output is CycloneDX 1.6, validated against the official schema in the project's own test
suite. `--with-vulnerabilities` adds a VEX section.

`metadata.properties` carries `icebergsca:vulnerabilitiesChecked`. A components-only SBOM is
an inventory, not an assessment — do not publish one as evidence that anything was checked.

## Caching between runs

The on-disk cache lives under the per-user cache directory. Persisting it makes repeat scans
substantially faster and reduces load on OSV:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/icebergsca
    key: icebergsca-${{ hashFiles('**/uv.lock', '**/package-lock.json') }}
    restore-keys: icebergsca-
```

Advisory detail is keyed by OSV's `modified` timestamp, so a cached advisory can never be
stale — a revised one lands under a different key. Query results carry a 24-hour TTL.

Use `--refresh` to discard cached data, and `--offline` for air-gapped runners. Offline mode
reports anything uncached as `unchecked_packages` rather than assuming it clean.

## Scanning in a monorepo

One invocation covers every ecosystem and produces a single merged report, with each finding
carrying the manifests that introduced it:

```bash
icebergsca scan . --format json | jq -r '
  .findings[] | .introduced_by[] | .path' | sort | uniq -c | sort -rn
```

That gives a per-file count, which is usually the fastest route to "which team owns this".
