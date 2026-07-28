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
| `--ecosystem <list>` | Ecosystems to restrict to: `pypi`, `npm`, `maven`, `go`, `cargo`, `nuget`, `rubygems`. Repeatable, or comma-separated |
| `--exclude <glob>` | Glob to skip. Repeatable |
| `--max-depth <n>` | Maximum directory depth to walk |
| `--follow-symlinks` | Follow symlinked directories |
| `--include-dev` | Include dev and test dependencies, which are excluded by default |
| `--scope <list>` | Scopes to include, overriding `--include-dev`: `runtime`, `dev`, `test`, `build`, `optional`. Repeatable, or comma-separated |

```bash
icebergsca scan . --ecosystem pypi,npm --exclude 'tests/fixtures/**'
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

Findings never change the exit code. See [Output and CI](output.md#exit-codes).
