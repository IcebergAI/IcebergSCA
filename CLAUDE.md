# IcebergSCA — maintenance notes

CLI for supply chain analysis: walk a project, find manifests and lockfiles, resolve the
dependency graph, check every package against OSV, report it.

## Commands

```bash
uv sync --extra dev
uv run ruff check . && uv run ruff format --check .
uv run mypy                      # strict, on src/ only
uv run pytest -q                 # ~350 tests, no network, under 2s
uv run icebergsca scan .         # dogfood
```

All four must pass before anything is considered done. `pytest` also runs in CI across
Python 3.11–3.14.

## The one rule that governs everything

**Never let the tool imply a clean result it did not earn.** Concretely:

- `ScanReport.vulnerabilities_checked` is False until the OSV stage actually runs. Renderers
  must print "lookup did not run", never "no vulnerabilities found". There are tests asserting
  the *absence* of reassuring strings — `test_table_never_reads_as_clean_when_nothing_could_be_checked`
  and friends in `tests/test_report.py`. Do not weaken them.
- Anything that fails goes in `scan_failed`, `skipped` or `warnings`. Nothing is dropped
  silently.
- Functions return `None` for "we could not determine this", distinct from `[]`/`""` for
  "there is genuinely none". `RegistryClient.versions`, `versions.compare` and
  `ranges.satisfies` all rely on this. Collapsing the two is the most likely way to introduce a
  false-clean.
- Over-report rather than under-report when uncertain: unreachable lockfile nodes default to
  runtime scope, environment markers are ignored, unresolvable constraints are still queried
  against OSV without a version.

## Architecture

Five stages in `core/scanner.py`: **discover → parse → resolve → scan → report**.

```
core/          models, discovery, scanner, graph resolver, version ordering, errors
ecosystems/    one module per ecosystem; maven/ is a package (parser + POM resolver)
osv/           OSV client (querybatch + detail), severity/fix extraction
registry/      version-list fetchers, used only for range resolution
resolve/       range matching + the resolver that drives it
cache/         SQLite store
report/        one renderer per format
cli/           Typer app — the only layer permitted to print or exit
```

Nothing below `cli/` prints or calls `sys.exit`. `core/` imports no frameworks.

### Adding an ecosystem

1. Write `ecosystems/<name>.py` exposing `SPEC = EcosystemSpec(...)` with its filename
   patterns and two parser functions.
2. Append it to `ECOSYSTEMS` in `ecosystems/__init__.py`.
3. Add `EcosystemId` member plus entries in `_OSV_ECOSYSTEM`, `_PURL_TYPE`, `_LABEL` in
   `core/models.py`. The three vocabularies genuinely disagree (`go` / `Go` / `golang`).
4. Add a fixture directory under `tests/fixtures/<name>/<case>/` using **real filenames** —
   parsers dispatch on the filename, so a fixture called `pyproject-poetry.toml` gets parsed as
   a requirements file and proves nothing.

Lockfile parsers should build `core.graph.Node` values and call `resolve()` + `build_dependencies()`
rather than hand-rolling traversal. That gets scope propagation, cycle safety and parent edges
for free.

### The bundled agent skill

`src/icebergsca/.agents/skills/icebergsca/` ships inside the wheel, following the convention
FastAPI, Typer and SQLModel use (`<package>/.agents/skills/<name>/SKILL.md` plus
`references/`). Consuming agents find it by globbing site-packages.

Keep it current when behaviour changes — a skill describing flags that no longer exist is worse
than none. `tests/test_skill.py` guards location, frontmatter, links, and that
`references/json-report.md` documents every top-level key the JSON renderer emits; CI asserts the
dot-directory survives packaging.

### Adding an output format

Module in `report/` with `render(report, *, color, width) -> str`, register in `_RENDERERS`, add
the enum member. `test_every_declared_format_renders` picks it up.

## Non-obvious decisions

**Manifests are parsed even when a lockfile wins.** `_apply_manifest_hints` in `scanner.py` merges
directness and scope from the manifest into the lockfile's versions, because `poetry.lock`,
`Pipfile.lock`, `Cargo.lock` and `yarn.lock` record none of it. Manifest scope only ever *widens*
inclusion, so a stray dev declaration cannot hide a shipping package.

**OSV alias merging is required, not cosmetic.** OSV returns a record per database, so one CVE
arrives as both GHSA and PYSEC — rendered raw, the same vulnerability twice at two severities
(GHSA usually carries a CVSS vector; PYSEC usually does not). `merge_aliases` in `osv/client.py`
groups by the transitive closure of IDs/aliases, keeping the best-informed record. Removing it
doubles the finding count.

**`querybatch` returns only `id` and `modified`** — not `summary` or `severity`, despite the field
names. Stage two (`GET /v1/vulns/{id}`) is what makes severity and fix versions possible; that
`modified` value is also the cache key suffix, which is why `osv_vuln` has no TTL.

**`querybatch` results are positional, and a short array is never padded.** Filling the tail with
empty advisory lists keeps the alignment honest but says "no known vulnerabilities" about packages
nobody looked up — and caches it for a day. Anything OSV did not answer for goes to
`_fall_back_to_stale` and ends up in `scan_failed`.

**Lockfile node keys must survive duplicate names.** `Cargo.lock` holds two majors of a crate
routinely, and keying the graph on the bare name drops all but the last. `rust.py` uses the bare
name only while a name is unique and Cargo's own `name version` form otherwise; npm resolves edges
by install path for the same reason. Any new parser keyed on name alone has this bug.

**An empty Maven scope is not `compile`.** `RawDependency.scope` holds exactly what the element
declared, because a `dependencyManagement` entry can supply the scope for a dependency that
declares none — which is how a BOM pins a family to `test`. `DEFAULT_SCOPE` is applied at the point
of use, not at parse time.

**Version keys are padded to four components** (`core/versions.py`). Without it `1.0` sorts
below `1.0.0` and a NuGet range of `[1.0,2.0]` excludes `2.0.0`.

**A version must start with a digit.** Otherwise a Git commit hash like `abcdef123456` parses
as version `(123456,)` and orders as a real version.

**Maven is approximate and says so.** Parent inheritance, BOM imports, nearest-wins and exclusions
— not profiles, mirrors, relocation or version ranges. Never shell out to `mvn`: running a
project's build to discover its dependencies is itself a supply chain risk.
`MavenResolver._backfill` re-reads `pom.xml` to apply BOM-supplied versions to direct dependencies,
which the synchronous parser cannot do because BOMs live on Central.

**Ranges, SARIF and CycloneDX are hand-written** rather than pulled from packages — a supply chain
scanner with a large dependency tree of its own is a poor advertisement. Correctness is held by
schema validation in `tests/test_report_formats.py` against the official schemas in `tests/schemas/`.

**Exit code 2 is usage, 1 is scan failure** — the reverse of the original plan, because Click
reserves 2 for usage errors and remapping it means overriding framework internals for nothing.

## Testing

- `tests/conftest.py` has an **autouse** `_no_network` fixture that swaps
  `scanner.build_http_client` for a mock transport and redirects the cache to a tmp dir. Never
  remove it: without it the suite hits the real OSV API and takes 8s instead of 1s.
- `MockTransport` 404s anything not explicitly stubbed, so a stray request fails loudly.
- OSV retry backoff is collapsed by a fixture in `tests/test_osv.py`; the backoff schedule
  itself is asserted separately by patching `asyncio.sleep`.
- Fixtures live in directories so each file keeps its real name.

## Verification against ground truth

Cross-check parsers against the tools that own the formats: `uv tree --no-dev`, `npm ls --all`,
`cargo tree`, `go list -m all`.

`icebergsca scan . --ecosystem pypi --format json` should agree with `uv tree` on both package set
and versions. This has caught two real bugs (a missing `coverage[toml]` extra traversal, and
`spring-web` left unversioned by an unapplied BOM).

## Known gaps

- `--fail-on <severity>` and an ignore/triage file — the obvious next feature.
- No SPDX output; CycloneDX only.
- No SBOM *ingest*.
- npm/yarn v1 lockfiles record no scope, so dev transitives are reported as runtime unless a
  `package.json` sits alongside.
- Gradle sees only literal declarations — no version catalogues or computed versions.
- OSV's unversioned second pass for `MAL-` advisories on yanked packages is not implemented;
  malicious advisories affecting the installed version still surface normally.
