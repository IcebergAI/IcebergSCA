---
title: How it works
icon: material/cog-outline
---

# How it works

A scan is five stages: **discover → parse → resolve → scan → report**. Each one
records what it could not do, and that record survives all the way into the
output.

The analysis is composition analysis: it inventories the third-party components
a project declares and checks each one against known advisories. It does not
read first-party source code, and it identifies a package by name and version
rather than by what the downloaded artefact actually contains — so build
provenance, signatures and typosquats are outside what a report can speak to.

## The five stages

### 1. Discover

The project directory is walked for files whose *names* identify them —
`requirements.txt`, `package-lock.json`, `Cargo.lock`, `pom.xml` and the rest.
Installed-dependency and build directories (`node_modules`, `.venv`, `target`,
`dist`, `__pycache__` and friends) are never walked: scanning `node_modules`
would report the same packages the lockfile already describes, thousands of
times over.

Files over 20 MB and scans finding more than 2,000 manifests are bounded, and
anything dropped for either reason lands in `skipped` with the reason attached.
`--exclude`, `--max-depth` and `--ecosystem` narrow the walk further; a single
file works as a target too.

### 2. Parse

Manifests and lockfiles are parsed into a dependency graph. **Manifests are
parsed even when a lockfile wins**, because `poetry.lock`, `Pipfile.lock`,
`Cargo.lock` and `yarn.lock` record neither directness nor scope — the manifest
supplies them. Manifest scope only ever *widens* inclusion, so a stray dev
declaration cannot hide a shipping package.

If a lockfile fails to parse, the scan falls back to its manifest and warns that
the versions are now declared rather than installed. It does not pretend the
lockfile was read.

### 3. Resolve

Only for dependencies a lockfile did not pin. Declared ranges are matched
against the version list from the registry — PyPI, npm, crates.io, NuGet,
RubyGems or the Go proxy — using each ecosystem's own rules: PEP 440, semver
(`^`, `~`, hyphen ranges, `||`, wildcards), Cargo's implicit caret, RubyGems'
`~>` and NuGet interval notation.

A constraint that cannot be evaluated is not discarded. The package is still
queried against OSV without a version, which over-reports rather than
under-reports. `--no-resolve` skips this stage entirely: faster, and every
range-only dependency is then checked without a version.

### 4. Scan

Every package is looked up in [OSV](https://osv.dev), in two passes.
`querybatch` returns advisory IDs; `GET /v1/vulns/{id}` returns the detail that
makes severity and fix versions possible.

Two behaviours here are worth spelling out:

- **Alias merging is required, not cosmetic.** OSV returns one record per
  database, so a single CVE arrives as both a GHSA and a PYSEC record — rendered
  raw, that is the same vulnerability listed twice at two different severities.
  Records are grouped by the transitive closure of their IDs and aliases, and
  the best-informed one is kept.
- **`querybatch` results are positional, and a short array is never padded.**
  Filling the tail with empty advisory lists would keep the alignment tidy while
  saying "no known vulnerabilities" about packages nobody looked up — and
  caching that for a day. Anything OSV did not answer for becomes an unchecked
  package instead.

### 5. Report

One renderer per format, all projections of the same report model. Nothing below
the CLI layer prints or exits, so the same scan produces `table`, `json`, `csv`,
`sarif` and `cyclonedx` from identical data.

## How much to trust a version

Every dependency carries a `pin` recording where its version came from. This is
the difference between a finding about your deployment and a finding about a
hypothetical fresh install.

| `pin` | Where the version came from | Confidence |
|---|---|---|
| `pinned` | Read from a lockfile — this is what is installed | Exact |
| `resolved` | A range resolved against the registry — what a fresh install would get | Indicative, not necessarily deployed |
| `unresolved` | The constraint could not be evaluated; OSV was queried without a version | Findings may not apply to the installed version |

Java is the systematic exception: it has no lockfile, so the graph is
reconstructed from Maven Central and every affected manifest is marked
`approximate`. Each module is resolved separately, so module boundaries hold:
a transitive is attributed to the declaration that introduced it, and one
module's version choice does not leak into another's.

## Scope

Dependencies carry one of `runtime`, `dev`, `test`, `build` or `optional`. Dev
and test are excluded by default; **build is included**, because a compromised
build tool reaches the artefact just as surely as a runtime library does.

```bash
icebergsca scan .                  # runtime, build and optional
icebergsca scan . --include-dev    # everything
icebergsca scan . --scope runtime  # only what ships
```

Scope propagates through the graph as the **most-included value across all
paths**. A package reachable both from a dev tool and from a runtime library is
runtime-scoped, and appears in a default scan.

## Where uncertainty goes

Functions in the codebase distinguish "we could not determine this" from "there
is genuinely none" — `None` versus `[]` — and that distinction is what the
report is built on. Collapsing the two is the most direct route to a false
clean, so nothing is allowed to.

| Situation | What the report does |
|---|---|
| OSV stage never ran | `vulnerabilities_checked: false`; output says the lookup did not run |
| OSV did not answer for a package | Listed individually in `unchecked_packages` |
| OSV unreachable, cache expired | Stale entries served **and labelled stale** in `warnings` |
| Lockfile unparseable | Manifest used instead, with a warning that versions are declared |
| File too large, or excluded | Listed in `skipped` with the reason |
| Constraint unresolvable | Queried against OSV without a version, marked `unresolved` |
| Graph truncated | Counted and shown |

Two deliberate over-reports round this out: unreachable lockfile nodes default
to runtime scope, and environment markers are ignored — a dependency behind
`sys_platform == "win32"` is reported on Linux too.

## Caching and network behaviour

Results are cached in SQLite under the per-user cache directory. Query results
carry a 24-hour TTL. Advisory *detail* has none, because it is keyed by the
`modified` timestamp OSV returns: a revised advisory lands under a new key. That
is exact invalidation rather than a guessed expiry.

```bash
icebergsca scan . --offline    # cache only; uncached packages reported as unchecked
icebergsca scan . --refresh    # discard cached OSV data first
icebergsca scan . --no-cache   # neither read nor write the cache
icebergsca cache info          # where it lives and what is in it
```

`--offline` never invents a clean result. Anything not already cached goes to
`unchecked_packages`, and the scan reports itself as incomplete.

Rate limits and server errors are retried with exponential backoff and jitter,
honouring `Retry-After`.
