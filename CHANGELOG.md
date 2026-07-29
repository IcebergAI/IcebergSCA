# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

**Scanning**

- `icebergsca scan` — walks a project directory (or a single file), resolves the dependency
  graph and checks every package against OSV.
- Seven ecosystems, lockfile-first: Python (`uv.lock`, `poetry.lock`, `Pipfile.lock`), npm
  (`package-lock.json` v1–v3, `pnpm-lock.yaml`, `yarn.lock` v1 and Berry), Go (`go.mod`), Rust
  (`Cargo.lock`), .NET (`packages.lock.json`), Ruby (`Gemfile.lock`), and Maven/Gradle via
  effective-POM reconstruction from Maven Central.
- Manifest parsing for every ecosystem, used both as a fallback and to supply the directness
  and scope that several lockfile formats omit.
- Version-range resolution against PyPI, npm, crates.io, NuGet, RubyGems and the Go proxy for
  projects with no lockfile. Supports PEP 440, semver (`^`, `~`, hyphen ranges, `||`,
  wildcards), Cargo's implicit caret, RubyGems' `~>` and NuGet interval notation.
- Dependency scope tracking with dev and test excluded by default; `--include-dev` and
  `--scope` to override. Scope propagates through the graph as the most-included value across
  all paths, so a package reachable from a runtime dependency is never hidden by a dev edge.

**Reporting**

- `table`, `json`, `csv`, `sarif` (2.1.0) and `cyclonedx` (1.6, with VEX) output formats.
  SARIF and CycloneDX are validated against the official schemas in the test suite.
- `icebergsca sbom` — CycloneDX SBOM, components only by default.
- SARIF fingerprints derived from package URL and advisory ID rather than line numbers, so
  reformatting a manifest does not close and reopen every GitHub alert.
- CVSS v4/v3/v2 vector parsing for severity, with GitHub Advisory labels as a fallback, and
  fix-version extraction from OSV `affected` ranges.
- OSV alias merging: the GHSA and PYSEC records for one CVE become a single finding, keeping
  whichever carried the severity and the fix version.

**For AI agents**

- Bundled agent skill at `icebergsca/.agents/skills/icebergsca/`, following the convention
  FastAPI, Typer and SQLModel use. Covers invocation, the JSON schema, exit-code semantics and
  the checks required before reporting a project as clean, with references for the report
  schema and CI integration.

**Infrastructure**

- SQLite cache with per-namespace freshness. Advisory detail is keyed by OSV's `modified`
  timestamp, giving exact invalidation rather than a guessed TTL. `icebergsca cache
  info|clear|prune`.
- `--offline`, `--no-cache`, `--refresh`, `--concurrency` and `--no-resolve`.
- Retry with exponential backoff and jitter on OSV rate limits and server errors, honouring
  `Retry-After`; expired cache entries are served, and labelled, when OSV is unreachable.

### Design notes

- **A scan never implies a clean result it did not earn.** Reports carry an explicit
  `vulnerabilities_checked` flag; packages that could not be checked are listed individually;
  and output says "lookup did not run" rather than "no vulnerabilities found" whenever that is
  the truth.
- Exit codes: `0` completed (regardless of findings), `1` scan failed or partial, `2` usage
  error, `3` `--fail-on` threshold met. Findings alone never fail a build.
- `--fail-on <severity>` gates a build on unsuppressed findings, checking scan completeness
  first so it can never pass a scan that failed to look anything up.
- A triage file, `.icebergsca.toml`, records findings that have been assessed and accepted, so
  gating is safe to leave switched on rather than being disabled the first week an unfixable
  transitive advisory appears. Each entry requires a reason, matches exactly on advisory (or
  alias) and package, and carries an expiry that defaults to 90 days. An accepted finding stays
  in the report marked `accepted`, is counted by `summary.suppressed`, appears in SARIF as
  dismissed rather than fixed, and returns when the entry expires. Rules that match nothing, or
  have expired, are reported as warnings.
- JSON schema `1.1`: adds a top-level `suppressed` audit trail, `summary.suppressed`, and
  `findings[].suppression`. Additive only — `summary.findings` and `by_severity` now count
  active findings, which is unchanged for any scan with no ignore file.
- Maven graphs are marked approximate — they are reconstructed, not read, and we never shell
  out to `mvn`. Each module of a multi-module build resolves against its own POM, so module
  boundaries hold: one module's nearest-wins choice cannot decide another's versions, and each
  transitive is attributed to the `<dependency>` declaration that introduced it.
- Maven `<exclusions>` are honoured on declared dependencies as well as inherited ones,
  including entries supplied by `dependencyManagement` and Maven's whole-segment wildcards.
  Excluded coordinates are absent from the report, and the `exclusions` field on each
  dependency records what was removed.
- Licensed under Apache 2.0.
