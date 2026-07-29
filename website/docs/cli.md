---
title: CLI reference
icon: material/console
---

# CLI reference

```
icebergsca [--version] COMMAND ...

  scan   Scan a project for dependencies and known vulnerabilities.
  sbom   Emit a CycloneDX 1.6 SBOM.
  cache  Inspect and manage the on-disk OSV cache.
```

## `scan`

```bash
icebergsca scan <path>
```

`<path>` is a project directory, or a single manifest or lockfile.

### Selecting what to scan

| Flag | Effect |
|---|---|
| `--ecosystem <name>` | Ecosystem to restrict to: `pypi`, `npm`, `maven`, `go`, `cargo`, `nuget`, `rubygems`. Repeatable |
| `--exclude <glob>` | Glob to skip. Repeatable |
| `--max-depth <n>` | Maximum directory depth to walk |
| `--follow-symlinks` | Follow symlinked directories |
| `--include-dev` | Include dev and test dependencies, which are excluded by default |
| `--scope <name>` | Scope to include, overriding `--include-dev`: `runtime`, `dev`, `test`, `build`, `optional`. Repeatable |

```bash
icebergsca scan . --ecosystem pypi --ecosystem npm --exclude 'tests/fixtures/**'
icebergsca scan . --scope runtime            # only what ships
icebergsca scan ./requirements.txt           # a single file
```

### Output

| Flag | Effect |
|---|---|
| `--format`, `-f` | `table` (default), `json`, `csv`, `sarif`, `cyclonedx` |
| `--output`, `-o` | Write the report here instead of stdout |
| `--no-color` | Disable coloured output |
| `--verbose`, `-v` | Increase log verbosity. Repeatable |
| `--quiet`, `-q` | Only log errors |

Logs go to stderr and the report to stdout, so piping the report is always safe.

### Gating and triage

| Flag | Effect |
|---|---|
| `--fail-on <severity>` | Exit `3` when an unsuppressed finding is at or above this severity. An incomplete scan still exits `1`, whatever it found |
| `--ignore-file <path>` | Accepted findings. Defaults to `.icebergsca.toml` beside the scan target when it exists |

`.icebergsca.toml` records findings somebody has assessed and accepted, so that gating is safe
to leave switched on rather than being disabled the first week an unfixable advisory appears:

```toml
[[ignore]]
advisory = "GHSA-6757-jp84-gxfx"   # or the CVE — aliases are matched too
package  = "pyyaml"                 # bare name, or a purl, optionally versioned
reason   = "Unreachable: we never call yaml.load on untrusted input"
expires  = 2026-10-27               # optional; defaults to 90 days out
```

`reason` is required, matching is exact rather than pattern-based, and an entry that expires
stops suppressing rather than failing the scan. Nothing is hidden: the finding stays in the
report marked `accepted`, `summary.suppressed` counts it, and SARIF reports it as dismissed
rather than fixed. A rule matching nothing produces a warning.

### Network and cache

| Flag | Effect |
|---|---|
| `--offline` | Use cached OSV data only. Uncached packages are reported as unchecked, never as clean |
| `--no-cache` | Ignore and do not write the disk cache |
| `--refresh` | Discard cached OSV data before scanning |
| `--concurrency <n>` | Concurrent requests, 1–64. Default `10` |
| `--no-resolve` | Do not resolve unpinned ranges against registries. Faster, but range-only dependencies are then checked without a version |

## `sbom`

```bash
icebergsca sbom <path>
```

Equivalent to `scan --format cyclonedx`, except that it defaults to components
only — an SBOM is often wanted for inventory rather than for findings.

| Flag | Effect |
|---|---|
| `--output`, `-o` | Write here instead of stdout |
| `--include-dev` | Include dev and test dependencies |
| `--with-vulnerabilities` / `--components-only` | Include OSV findings as a VEX section. Components-only (the default) makes no network calls to OSV |

## `cache`

```bash
icebergsca cache info    # where the cache lives and what is in it
icebergsca cache clear   # delete every cached entry
icebergsca cache prune   # delete expired entries, keeping advisory detail
```

`prune` keeps advisory detail deliberately: it is keyed by OSV's `modified`
timestamp rather than an expiry, so it cannot go stale and re-fetching it is
pure waste.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed. Vulnerabilities may have been found — that is not an error |
| `1` | Scan failed, or completed only partially |
| `2` | Usage error: bad flag, unknown format |
| `3` | Only with `--fail-on`: an unsuppressed finding met the threshold |

Findings never change the exit code unless you ask with `--fail-on`, and even then
under a code of their own. See [Output and CI](output.md#exit-codes).
