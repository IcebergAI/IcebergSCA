---
name: icebergsca
description: IcebergSCA usage and output interpretation. Use when scanning a project for vulnerable dependencies, auditing a supply chain, generating an SBOM, or reading an IcebergSCA report. Covers the JSON schema, exit codes, and the checks required before reporting a project as clean.
---

# IcebergSCA

Official IcebergSCA skill for running supply chain scans and reading the results correctly.

IcebergSCA walks a project, finds every dependency manifest and lockfile, resolves the
dependency graph, checks each package against [OSV](https://osv.dev), and reports findings.

## Quick Reference

* Programmatic use: always `--format json`; see [Machine-readable output](#machine-readable-output).
* **Before saying a project is clean, check three fields** — see [Never report a false clean](#never-report-a-false-clean). This is the single most important section.
* Exit codes: `0` completed, `1` scan failed or partial, `2` usage error. Findings never fail.
* Full field reference: [the JSON report reference](references/json-report.md).
* CI, SARIF and SBOM: [the CI integration reference](references/ci-integration.md).
* `pin` tells you how much to trust a version: `pinned` > `resolved` > `unresolved`.

## Running a scan

```bash
icebergsca scan ./myproject
```

The tool is a CLI application, not a library. Install it as a tool, not as a dependency:

```bash
uv tool install icebergsca      # or run ad hoc: uvx icebergsca scan .
```

## Machine-readable output

Always request JSON when a program or agent will read the result. The table format is for
humans and its layout is not a stable interface.

```bash
icebergsca scan ./myproject --format json --output report.json
```

Report output goes to stdout and logs go to stderr, so piping is safe:

```bash
icebergsca scan ./myproject --format json | jq '.summary'
```

```bash
# DO NOT DO THIS: parsing the human table is fragile and will break.
icebergsca scan ./myproject | grep critical
```

## Never report a false clean

An empty `findings` array does **not** mean the project is safe. It means one of three very
different things, and the report tells you which. Check all three fields before summarising a
scan as clean:

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

The `warnings` array explains every degradation in plain language. Surface it whenever
`scan.complete` is `false` rather than discarding it.

## Exit codes

```bash
icebergsca scan .; echo "exit=$?"
```

| Code | Meaning |
|---|---|
| `0` | The scan completed. Vulnerabilities may have been found — that is not an error |
| `1` | The scan failed, or completed only partially. Treat the report as incomplete |
| `2` | Usage error: unknown flag or format |

Findings deliberately never change the exit code, so a non-zero exit always means *the tool
could not do its job*, not *your project has problems*. Do not use the exit code to decide
whether vulnerabilities exist — read `summary.findings`.

## Reading a finding

```json
{
  "package":  { "ecosystem": "PyPI", "name": "requests", "version": "2.19.1",
                "purl": "pkg:pypi/requests@2.19.1" },
  "advisory": { "id": "GHSA-x4qr-2fvf-3mr5", "aliases": ["CVE-2018-18074"],
                "summary": "Requests sends an HTTP Authorization header...",
                "severity": { "level": "high", "score": 8.1, "vector": "CVSS:3.1/..." } },
  "fixed_version": "2.20.0",
  "direct": true,
  "introduced_by": [ { "path": "requirements.txt", "line": 2, "scope": "runtime" } ]
}
```

* Prefer `advisory.aliases` for a CVE identifier when quoting one to a user — it is the ID
  they can look up anywhere. `advisory.id` is OSV's own.
* `fixed_version` is the lowest release above the installed version that fixes the issue, and
  is the remediation to recommend. `null` means no fix is known — say so rather than inventing
  an upgrade.
* `advisory.severity.level` may be `"unknown"`, which is distinct from `"none"`. Unknown means
  nobody scored it, not that it is harmless.
* `introduced_by` lists every place the package enters the project. Use it to tell a user
  *which file to edit*.

## Trusting a version: the `pin` field

Each dependency carries a `pin` recording where its version came from. This changes how much
confidence a finding deserves:

| `pin` | Meaning | Confidence |
|---|---|---|
| `pinned` | Read from a lockfile — this is what is installed | Exact |
| `resolved` | A range resolved against the registry — what a *fresh install* would get | Indicative, not necessarily deployed |
| `unresolved` | The constraint could not be evaluated; OSV was queried without a version | Findings may not apply to the installed version |

When reporting `resolved` or `unresolved` findings, say so. A user running an older lockfile
may have a different version than the one scanned.

## Scope filtering

Dev and test dependencies are excluded by default. Build-scoped dependencies are **included**,
because a compromised build tool reaches the artefact just as surely as a runtime library.

```bash
icebergsca scan .                      # runtime, build and optional
icebergsca scan . --include-dev        # everything
icebergsca scan . --scope runtime      # only what ships
```

## Narrowing a scan

```bash
icebergsca scan . --ecosystem pypi,npm          # restrict ecosystems
icebergsca scan . --exclude 'tests/fixtures/**' # skip paths
icebergsca scan ./requirements.txt              # a single file
```

Deliberately vulnerable test fixtures are a common source of noise. Exclude them rather than
explaining them away.

## Network behaviour

Results are cached on disk, so repeat scans are fast and mostly offline.

```bash
icebergsca scan . --offline     # cache only; uncached packages reported as unchecked
icebergsca scan . --refresh     # discard cached OSV data first
icebergsca scan . --no-resolve  # skip registry range resolution (faster, less precise)
icebergsca cache info
```

`--offline` never invents a clean result: anything not in the cache lands in
`unchecked_packages`.

## Generating an SBOM

```bash
icebergsca sbom ./myproject                          # CycloneDX 1.6, components only
icebergsca sbom ./myproject --with-vulnerabilities   # ...plus a VEX section
```

The SBOM carries an `icebergsca:vulnerabilitiesChecked` property in `metadata.properties`.
Apply the same rule as the JSON report: do not present a components-only SBOM as evidence that
anything was checked.

## Ecosystem caveats worth knowing

* **Maven and Gradle graphs are approximate.** Java has no lockfile, so the graph is
  reconstructed from Maven Central. Affected manifests carry `"approximate": true`. Mention
  this when reporting Java results.
* **Go reads `go.mod`, never `go.sum`.** `go.sum` lists versions merely *considered* during
  resolution, so scanning it reports vulnerabilities in code that was never built.
* **`yarn.lock` v1 records no scope.** Without a sibling `package.json`, dev transitives are
  reported as runtime — over-reporting rather than hiding.
* **Environment markers are ignored.** A dependency behind `sys_platform == "win32"` is
  reported on Linux too. This is deliberate: over-reporting is the safe direction.
