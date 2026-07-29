# The JSON report

`icebergsca scan --format json` produces the canonical, full-fidelity document. Every other
format is a projection of it. The shape is versioned by `schema_version`; check it before
relying on field positions.

```bash
icebergsca scan . --format json --output report.json
```

## Top level

```json
{
  "schema_version": "1.0",
  "tool": { "name": "icebergsca", "version": "0.1.0" },
  "scan": { ... },
  "summary": { ... },
  "manifests": [ ... ],
  "dependencies": [ ... ],
  "findings": [ ... ],
  "unchecked_packages": [ ... ],
  "skipped": [ ... ],
  "warnings": [ ... ]
}
```

## `scan`

```json
{
  "root": "/home/user/myproject",
  "started_at": "2026-07-28T16:04:11.512Z",
  "finished_at": "2026-07-28T16:04:14.007Z",
  "status": "ok",
  "vulnerabilities_checked": true,
  "complete": true
}
```

| Field | Notes |
|---|---|
| `status` | `ok`, `partial` or `failed` — about the *scan*, never about findings |
| `vulnerabilities_checked` | `false` means the OSV stage never ran. No conclusion is available |
| `complete` | `true` only when the lookup ran, nothing failed and no package went unchecked |

A scan that finds forty critical vulnerabilities still has `status: "ok"`. That is not a bug —
it means the tool did its job.

## `summary`

```json
{
  "dependencies": 21, "direct": 9, "transitive": 12, "packages": 21,
  "findings": 12,
  "by_severity": { "critical": 3, "high": 4, "medium": 4, "low": 1 },
  "unchecked_packages": 0,
  "skipped_files": 0
}
```

`dependencies` counts entries *including* provenance duplicates — a package declared in two
manifests appears twice. `packages` counts unique packages. Use `packages` when reporting
"we checked N packages".

`by_severity` omits levels with no findings and is ordered most severe first.

## `manifests`

One entry per ecosystem-and-directory scan unit.

```json
{
  "ecosystem": "PyPI",
  "directory": ".",
  "manifests": ["pyproject.toml"],
  "lockfiles": ["uv.lock"],
  "parsed": ["uv.lock"],
  "dependency_count": 21,
  "from_lockfile": true,
  "approximate": false,
  "error": null
}
```

* `parsed` is what was **actually read**, which differs from `lockfiles` when a lockfile could
  not be parsed and the manifest was used instead. Report `parsed`, not `lockfiles`.
* `from_lockfile: false` means versions are declared, not installed.
* `approximate: true` means the graph was reconstructed rather than read — currently Maven. It
  does *not* mean provenance is guesswork: each module is resolved on its own, so a
  transitive's `source` names the declaration that introduced it.
* `dependency_count` values sum to `summary.dependencies`.

## `dependencies`

```json
{
  "package": { "ecosystem": "PyPI", "name": "urllib3", "version": "1.24.1",
               "purl": "pkg:pypi/urllib3@1.24.1" },
  "scope": "runtime",
  "direct": false,
  "pin": "pinned",
  "constraint": null,
  "source": { "path": "requirements.txt", "line": 4 },
  "parents": ["pkg:pypi/requests@2.19.1"],
  "exclusions": []
}
```

* `ecosystem` is the **OSV** name (`PyPI`, `npm`, `Maven`, `Go`, `crates.io`, `NuGet`,
  `RubyGems`), not the `--ecosystem` flag value (`pypi`, `npm`, `maven`, `go`, `cargo`,
  `nuget`, `rubygems`). The two vocabularies differ.
* `purl` is the canonical identity and the right key for correlating with other tools.
* `scope` is one of `runtime`, `dev`, `test`, `build`, `optional`.
* `constraint` is the raw declared text (`">=2.0,<3.0"`, `"^4.17.21"`) when the version was not
  pinned outright.
* `source.line` is `null` for JSON and XML manifests, where a line number would be guesswork.
* `parents` is populated for lockfile formats that record edges and for reconstructed Maven
  transitives. Empty means "unknown", never "nothing depends on it".
* `source` on a reconstructed Maven transitive is the declaration that introduced it — the
  module's own POM and the `<dependency>` line — not merely the first file scanned.
* `exclusions` lists the `group:artifact` keys this declaration removes from its own subtree
  (Maven `<exclusions>`, wildcards included). A package named here is absent from the graph
  deliberately, which is the one case where something is missing without being an error.

## `findings`

```json
{
  "package": { "ecosystem": "PyPI", "name": "pyyaml", "version": "5.1",
               "purl": "pkg:pypi/pyyaml@5.1" },
  "advisory": {
    "id": "GHSA-6757-jp84-gxfx",
    "modified": "2024-11-01T00:00:00Z",
    "aliases": ["CVE-2020-14343", "PYSEC-2021-142"],
    "summary": "Improper Input Validation in PyYAML",
    "details": "A vulnerability was discovered in the PyYAML library...",
    "published": "2021-02-09T00:00:00Z",
    "malicious": false,
    "severity": { "level": "critical", "score": 9.8, "vector": "CVSS:3.1/AV:N/..." },
    "references": ["https://github.com/yaml/pyyaml/issues/420"]
  },
  "fixed_version": "5.4",
  "direct": true,
  "introduced_by": [
    { "path": "requirements.txt", "line": 3, "scope": "runtime", "direct": true }
  ]
}
```

Sorted most severe first, then by package name.

* `severity.level`: `critical`, `high`, `medium`, `low`, `none`, `unknown`. `unknown` means the
  advisory carries no rating — distinct from `none`, which is a scored zero.
* `severity.score` and `severity.vector` are `null` when the rating came from a qualitative
  label rather than a CVSS vector.
* `malicious: true` marks an OSV `MAL-` advisory: a package published to attack its consumers,
  rather than a bug. These are always treated as critical. Escalate them — the remediation is
  removal, not upgrade.
* One CVE reported by several advisory databases is merged into a **single** finding, keeping
  whichever record carried the severity and fix version. The other IDs appear in `aliases`.

## `unchecked_packages`, `skipped` and `warnings`

```json
"unchecked_packages": [
  { "ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0" }
],
"skipped": [
  { "path": "huge.lock", "reason": "exceeds size limit (24,000,000 > 20,000,000 bytes)" }
],
"warnings": [
  "offline: 22 package(s) had no cached OSV result"
]
```

These three arrays are the report's account of what it could **not** do. Never discard them
when summarising: they are the difference between "clean" and "we did not look".

## Correlating with other tools

`purl` is the interoperable identifier. To diff against another scanner:

```bash
icebergsca scan . --format json | jq -r '.findings[] | "\(.package.purl) \(.advisory.id)"' | sort
```

To list remediations:

```bash
icebergsca scan . --format json | jq -r '
  .findings[] | select(.fixed_version) |
  "\(.package.name): \(.package.version) -> \(.fixed_version)"' | sort -u
```
