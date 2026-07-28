---
title: Ecosystems
icon: material/package-variant-closed
---

# Ecosystems

Seven ecosystems, manifests and lockfiles both. Parsers dispatch on the
filename, so a file only has to be where a build tool would put it.

| Ecosystem | `--ecosystem` | Manifests | Lockfiles | Graph edges |
|---|---|---|---|---|
| Python | `pypi` | `requirements*.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile` | `uv.lock`, `poetry.lock`, `Pipfile.lock` | yes |
| npm | `npm` | `package.json` | `package-lock.json` (v1–v3), `pnpm-lock.yaml`, `yarn.lock` (v1 + Berry) | yes |
| Maven / Gradle | `maven` | `pom.xml`, `build.gradle(.kts)` | *none* — resolved from Central | yes (approximate) |
| Go | `go` | — | `go.mod` (already MVS-resolved) | no |
| Rust | `cargo` | `Cargo.toml` | `Cargo.lock` | yes |
| .NET | `nuget` | `*.csproj`, `packages.config` | `packages.lock.json` | yes |
| Ruby | `rubygems` | `Gemfile`, `*.gemspec` | `Gemfile.lock` | yes |

Restrict a scan by repeating the flag:

```bash
icebergsca scan . --ecosystem pypi --ecosystem npm
```

!!! note "Three vocabularies that genuinely disagree"

    The `--ecosystem` value, the OSV ecosystem string and the Package URL type
    are not the same word. Go is `go` / `Go` / `golang`; Rust is `cargo` /
    `crates.io` / `cargo`; Ruby is `rubygems` / `RubyGems` / `gem`. JSON
    reports carry the **OSV** name in `package.ecosystem` and the purl type
    inside `package.purl`. Correlate on `purl`.

## Caveats

### Go reads `go.mod`, never `go.sum`

`go.sum` lists every version *considered* during module resolution, not the ones
selected. Scanning it reports vulnerabilities in code that was never built.
`go.mod` is already MVS-resolved, which is also why Go produces no graph edges —
the file records the selected set, not the shape that produced it.

### Maven and Gradle are approximate, and say so

Java has no lockfile. The graph is reconstructed by fetching POMs from Maven
Central and applying parent inheritance, BOM imports, nearest-wins and
exclusions. Not modelled: profiles, mirrors, relocation and version ranges.
Affected manifests carry `approximate: true`, and the table marks them `~`.

IcebergSCA never shells out to `mvn`. Running a project's own build in order to
discover its dependencies is itself a supply chain risk.

Gradle sees only literal declarations — no version catalogues, no computed
versions.

An empty Maven `<scope>` is not `compile`, and is not treated as such at parse
time: a `dependencyManagement` entry can supply the scope for a dependency that
declares none, which is exactly how a BOM pins a family to `test`.

### npm and yarn v1 record no scope

Neither format distinguishes dev from runtime for transitives. With a
`package.json` alongside, directness and scope are merged in from the manifest.
Without one, dev transitives are reported as runtime — over-reporting rather
than hiding.

### Duplicate names in one lockfile

`Cargo.lock` routinely holds two majors of the same crate, and a graph keyed on
the bare name drops all but the last. Rust uses the bare name only while it is
unique and Cargo's own `name version` form otherwise; npm resolves edges by
install path for the same reason.

### Environment markers are ignored

A dependency behind `sys_platform == "win32"` is reported on Linux too. This is
deliberate — over-reporting is the safe direction — but it does mean a scan can
name a package your platform never installs.

## Adding one

The layout is one module per ecosystem exposing an `EcosystemSpec` with its
filename patterns and two parser functions, plus an entry in three mapping
tables and a fixture directory using **real filenames**. Lockfile parsers build
graph nodes and call the shared resolver rather than hand-rolling traversal,
which is what gets scope propagation, cycle safety and parent edges for free.

The full procedure is in
[`CLAUDE.md`](https://github.com/IcebergAI/IcebergSCA/blob/main/CLAUDE.md) in
the repository.
