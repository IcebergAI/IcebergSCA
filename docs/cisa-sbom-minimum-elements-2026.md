# Assessment: IcebergSCA against the 2026 Minimum Elements for an SBOM

Assessed 2026-07-30 against `main` at `a56356b`.

## What was assessed against

The ACSC news item that prompted this
([cyber.gov.au](https://www.cyber.gov.au/about-us/view-all-content/news/updated-guidance-on-the-2026-minimum-elements-for-a-software-bill-of-materials))
relays joint guidance published by CISA with NSA, FBI and international partners on
2026-07-29: [2026 Minimum Elements for a Software Bill of Materials
(SBOM)](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom),
which replaces the [2021 NTIA minimum
elements](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf)
outright.

**Caveat on sourcing.** Neither cyber.gov.au nor cisa.gov is reachable from the environment this
assessment was produced in — the egress policy returns 403 for both, and for the
regulations.gov copies of the PDF. The requirement set below is therefore reconstructed from
CISA's [2025 draft](https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom)
(which the 2026 document is the finalisation of) plus published analysis of the final. The
*shape* of the requirements — which fields exist, what they mean — is well attested across
sources. Exact wording, and any element added or dropped between the draft and the final,
should be checked against the PDF before this assessment is quoted externally. Every gap
identified below is a gap under the 2021 NTIA baseline too, or under both, so none of the
conclusions rest on the 2026 text alone.

The relevant surface of this tool is the CycloneDX renderer (`report/cyclonedx.py`), reachable as
`icebergsca sbom` and `icebergsca scan --format cyclonedx`. The JSON report is richer than the
SBOM in several respects that matter here, and that asymmetry is itself a finding.

## Verdict

| # | Element | Status |
|---|---|---|
| 1 | SBOM Author | Partial |
| 2 | Software Producer (was *Supplier Name*) | **Not met** |
| 3 | Component Name | Met |
| 4 | Component Version | Met, with a caveat |
| 5 | Software Identifiers | Met for components; **not met** for the document |
| 6 | Component Hash *(new in 2025/2026)* | **Not met** |
| 7 | License *(new)* | **Not met** |
| 8 | Dependency Relationship / Coverage (was *Depth*) | Partial — and one real defect |
| 9 | Known Unknowns | **Not met in the SBOM** (present in the JSON report) |
| 10 | Timestamp | Met |
| 11 | Tool Name *(new)* | Met, with a caveat |
| 12 | Generation Context *(new)* | **Not met** |
| — | Automation support (machine-readable, standard format) | Met |
| — | Frequency | Met, so far as a CLI can |
| — | Distribution, delivery, access control | Out of scope |
| — | Accommodation of updates to SBOM data | **Not met** |

Six met, three partial, six not met. The tool produces a schema-valid CycloneDX 1.6 document
with correct identity and structure, and is unusually honest about resolution confidence — but it
carries none of the four fields the 2026 revision added, and no producer or license data at all.
Nothing in the repository claims CISA or NTIA conformance, so there is no over-claim to correct;
the gap is capability, not honesty — with the one exception in §8.

---

## Data fields

### 1. SBOM Author — Partial

`_metadata` (`report/cyclonedx.py:77`) emits `metadata.tools.components[]` naming `icebergsca`
and its version. There is no `metadata.authors` and no `metadata.manufacturer`.

CISA treats the *author* of the SBOM (the entity that created and stands behind the document) as
distinct from the *tool* that generated it — which is why Tool Name was added as a separate field
rather than folded in. A consumer reading this document can tell what produced it but not who
ran it or who vouches for it.

Nothing in the tool knows the answer, so the fix is an input, not an inference: a `--author`
option (or a `[tool.icebergsca.sbom]` block), written into `metadata.authors`, and an explicit
statement when absent rather than silence.

### 2. Software Producer — Not met

This is the largest field gap, and it applies twice over.

*Per component*: `_component` (`report/cyclonedx.py:110`) emits `type`, `name`, `purl`,
`version` and four `icebergsca:` properties. No `supplier`, no `publisher`, no `author`.
`Dependency` and `PackageRef` (`core/models.py:268`, `core/models.py:191`) have nowhere to put
one.

*For the primary component*: `metadata.component` is `{type, bom-ref, name}` where the name is
`report.root.name` — the scan directory's basename (`report/cyclonedx.py:92`). No version, no
purl, no producer. A consumer cannot identify what the SBOM is *of*, only what it contains.

The 2026 guidance renamed the 2021 *Supplier Name* field to *Software Producer* and, per the
published analysis, provides an explicit fallback value for the case where provenance is not
reliably known. That fallback is the immediate win here: the tool currently omits the field, and
an absent field is weaker than a recorded "unknown" — a consumer cannot distinguish "we looked
and could not tell" from "this tool does not model producers". That distinction is the same one
`core/models.py:6-13` already commits the codebase to.

Real producer data needs registry metadata. `registry/client.py` deliberately fetches only
version lists (`versions()`, `registry/client.py:103`) and only when resolving ranges, so this is
a new network dependency — see §7, which has the same shape and the same cost.

Partial structural sources exist and are free: Maven's `groupId` and npm's scope are already
carried in the purl namespace (`core/models.py:220`). They identify a namespace, not a producer,
and should not be relabelled as one — but a namespace plus an explicit "unknown provenance" is
strictly more than the document says today.

### 3. Component Name — Met

Every component carries `name`. Ecosystem-specific hierarchy is handled correctly:
`_purl_namespace` (`core/models.py:220`) splits Maven `group:artifact`, npm `@scope/name` and Go
module paths into proper purl namespaces, and applies PEP 503 normalisation for PyPI.

### 4. Component Version — Met, with a caveat

`version` is emitted whenever known (`report/cyclonedx.py:124`), and the tool is better than most
on the surrounding question of *how well* it is known: `Pin`
(`core/models.py:122`) distinguishes `pinned` (read from a lockfile), `resolved` (a range
evaluated against a registry) and `unresolved` (a constraint that could not be evaluated), and
that reaches the document as `icebergsca:pin`.

The caveat: an `unresolved` component has its `version` key omitted entirely. A consumer that
does not read `icebergsca:` properties sees a component with no version and no explanation. The
information is in the document but in a vendor namespace, so only icebergsca-aware consumers get
it.

### 5. Software Identifiers — Met for components, not met for the document

Every component gets a purl, used as both `purl` and `bom-ref`. The purl is derived from
`PackageRef` on demand and never stored (`core/models.py:203`), so identity and identifier cannot
drift — a good decision that most tools get wrong. Purl is the identifier type the guidance is
built around, so this is satisfied.

Two absences worth noting rather than fixing reflexively:

- **No CPE.** Consumers matching against NVD rather than OSV rely on it. Deriving CPEs from purls
  is guesswork, and a wrong CPE is worse than none, so the correct answer here is probably to
  leave it out — but say so.
- **No `serialNumber` on the document.** CycloneDX defines it (`tests/schemas/bom-1.6.schema.json:30`)
  and the tool never emits one, so the SBOM has no identity of its own. See "Accommodation of
  updates" below.

### 6. Component Hash — Not met

Nothing in the model holds a digest. This is a new element in the 2026 revision, tied to its
integrity-verification theme: a consumer should be able to confirm they hold the exact artefact
the SBOM describes.

It is also the most tractable gap, because the hashes are already sitting in the files the
parsers read:

| Ecosystem | Where the hash already is | Cost |
|---|---|---|
| Rust | `Cargo.lock` `checksum` (present in `tests/fixtures/rust/basic/Cargo.lock`) | free |
| npm | `package-lock.json` / `pnpm-lock.yaml` `integrity`, `yarn.lock` `checksum` | free |
| Python | `uv.lock` / `poetry.lock` file hashes, `Pipfile.lock` `hashes` | free |
| Python | `requirements.txt` `--hash=sha256:…` — currently stripped before parsing (`ecosystems/python.py:48-51`) | free |
| .NET | `packages.lock.json` `contentHash` | free |
| Go | `go.sum` — not currently in the file spec, which lists only `go.mod` (`ecosystems/golang.py:158`) | small |
| Maven / Gradle | Not in a POM at all; needs `.sha1` fetches from Central | network |
| Ruby | `Gemfile.lock` records none | not available |

Five of seven ecosystems are achievable with no network access and no new I/O — just retaining
data the parsers currently discard.

The house `None`-versus-empty rule applies directly and should be stated in the field's docstring:
`None` means "this parser does not read hashes", an empty collection means "this file records
none". Collapsing them would let a consumer read "unverifiable" as "verified".

### 7. License — Not met

No license field, no license parsing, anywhere.

Unlike hashes, this data is genuinely not in the files being parsed. `pyproject.toml` and
`package.json` declare the *root project's* license; `Cargo.lock`, `package-lock.json` and
`poetry.lock` record nothing about their dependencies' licensing. So per-component licenses
require registry metadata — PyPI's JSON API, the npm registry, crates.io, RubyGems — which means
a network call per package on a code path that currently makes none.

Two things make this cheaper than it looks:

- **Maven is nearly free.** `MavenResolver` already fetches POMs from Central to resolve parents
  and BOM imports. `<licenses>` is in the POM it already has.
- **SPDX license IDs are already validated.** `tests/schemas/spdx.schema.json` is vendored — as
  the sibling schema `bom-1.6.schema.json` `$ref`s for the license-ID enum, not as SPDX output
  support — so `licenses[].license.id` values are schema-checked the moment they are emitted.

Recommend an opt-in flag (`--licenses`) so the default path stays network-frugal, and an absolute
prohibition on inference: an unknown license must render as unknown. "No license found" read as
"no license obligations" is the licensing analogue of the false-clean this codebase exists to
avoid, and it needs a test in the spirit of `test_table_never_reads_as_clean_when_nothing_could_be_checked`.

### 8. Dependency Relationship / Coverage — Partial, and one real defect

The 2026 revision replaces 2021's *Depth* with *Coverage*, asking for breadth as well as depth
and for the SBOM to state how complete its own graph is.

**Depth is genuinely good.** `_dependency_graph` (`report/cyclonedx.py:133`) emits real edges
from lockfile-recorded parents; `parents` empty means "we don't know", never "nothing depends on
it" (`core/models.py:281`); scope, directness and `exclusions` are all carried; and `exclusions`
being in the output at all (`report/json_.py:135`) keeps the one subtractive operation in the
codebase auditable.

**The defect.** Lines 150–152 add an entry for *every* component, so components from formats that
record no edges get `"dependsOn": []`. CycloneDX defines that as a positive claim — from the
schema's own text at `tests/schemas/bom-1.6.schema.json:1836`:

> Components or services that do not have their own dependencies must be declared as empty
> elements within the graph. Components or services that are not represented in the dependency
> graph may have unknown dependencies. […] It is recommended to leverage compositions to
> indicate unknown dependency graphs.

So an empty `dependsOn` asserts *dependency-free*, and the tool emits it for packages whose
dependencies it simply never learned. This directly contradicts the function's own docstring
("Formats that record no edges simply contribute fewer entries rather than a fabricated flat
tree", `report/cyclonedx.py:136`) — the code does contribute those entries. It is a false-clean
of exactly the shape the project's governing rule prohibits, in the one output format designed to
be consumed by other machines. Fix: omit the entry when parentage is unknown, and declare
`compositions` with `aggregate: incomplete` — the remedy the specification itself names.

**Coverage is not stated.** Three further honesty gaps, all in the same area:

- **Scope filtering is silent.** `DEFAULT_SCOPES` excludes dev and test
  (`core/scanner.py:54`), and `icebergsca sbom` inherits that default. The document does not
  record that a filter was applied, so a project whose dev dependencies were excluded is
  indistinguishable from one that has none.
- **Per-manifest confidence is dropped.** `ManifestResult.approximate` and `from_lockfile`
  (`core/models.py:433-435`) reach the JSON report (`report/json_.py:117-118`) but not the SBOM.
  A Maven graph — which the codebase is explicit about approximating — is presented in CycloneDX
  with the same authority as a `Cargo.lock` read verbatim.
- **`scan_failed`, `skipped` and `warnings` are absent from the SBOM.** Only three counts survive
  into `metadata.properties`. Everything the JSON report says about what could not be read, the
  SBOM does not.

### 9. Known Unknowns — Not met in the SBOM

The tool models known unknowns unusually well internally — `scan_failed`, `SkippedFile`,
`Pin.UNRESOLVED`, `ManifestResult.error`, `warnings` — and surfaces all of it in the JSON
report. None of it reaches the CycloneDX document except three counters.

`icebergsca:complete` (`report/cyclonedx.py:101`) is the closest thing, and it is about
*vulnerability* coverage, not *component* coverage: `is_complete` (`core/models.py:480`) requires
`vulnerabilities_checked`, so a `--components-only` SBOM always reports `complete: false`. That
under-claims rather than over-claims, which is the safe direction, but it also means the field
carries no information about the inventory — the thing an SBOM consumer is actually asking about.

CycloneDX `compositions` (`tests/schemas/bom-1.6.schema.json:2224`) with its `aggregate`
enumeration is purpose-built for this, and covers §8 and §9 together.

### 10. Timestamp — Met

`metadata.timestamp` is ISO 8601, UTC, `Z`-suffixed (`report/cyclonedx.py:79`) — exactly the
form the 2026 revision clarified it wants.

### 11. Tool Name — Met, with a caveat

`metadata.tools.components[]` carries name and version, in the CycloneDX 1.5+ object form rather
than the deprecated `tools[]` array.

The caveat is small but on-theme: `report.tool_version or "0.0.0"` (`report/cyclonedx.py:85`)
substitutes a fabricated version when the real one is unknown. `0.0.0` is a plausible-looking
lie; omitting the key is honest.

### 12. Generation Context — Not met

The new *Generation Context* element asks which SDLC phase the SBOM was generated in, and how and
where — so a consumer can judge how complete it is likely to be. Nothing in the document
addresses it.

This is cheap and the answer is unambiguous. icebergsca reads source manifests and lockfiles; it
never observes a build and never inspects a built artefact, so its SBOMs are always
source-analysis SBOMs, pre-build, produced by a third party rather than by the software producer.
That is a meaningful limitation — a source-derived SBOM cannot see vendored code, patched
dependencies or anything the build injects — and stating it plainly is more valuable than most of
the fields above. `metadata.lifecycles` (`tests/schemas/bom-1.6.schema.json:585`) plus a property
recording per-unit source-of-truth (lockfile versus manifest versus reconstructed) says it in one
place.

---

## Automation support

**Met.** CycloneDX 1.6 JSON, hand-written (`report/cyclonedx.py:8-11`) and validated in the test
suite against the official published schema with offline sibling resolution
(`tests/test_report_formats.py:50-60`). The guidance names SPDX and CycloneDX as the acceptable
machine-readable formats and discourages SWID; supporting one satisfies the requirement.

SPDX output remains a known gap (`CLAUDE.md`, "Known gaps"). Worth doing only if a consumer
demands it — CycloneDX carries VEX natively, which is the reason it was chosen, and the guidance
does not require both.

## Practices and processes

- **Frequency.** Met as far as a CLI can be: it runs on demand, and
  `references/ci-integration.md` documents wiring it into a pipeline. Whether an SBOM is
  regenerated per build is the adopter's process, not the tool's.
- **Distribution, delivery, access control.** Out of scope. The tool writes to stdout or `--output`
  (`cli/main.py:328`); it does not publish, transmit or gate access. One adjacent note: there is
  no way to sign or attest the document, which sits oddly beside the 2026 revision's integrity
  emphasis — a consumer can verify components once hashes exist, but not the SBOM itself.
- **Accommodation of updates to SBOM data. Not met.** The document has no `serialNumber` and
  hardcodes `"version": 1` (`report/cyclonedx.py:63`). A corrected or regenerated SBOM for the
  same product is indistinguishable from the original, which is precisely what this element
  exists to prevent. Related: `metadata.timestamp` makes output non-reproducible, so two SBOMs of
  an unchanged project never diff cleanly. Fix: emit a `urn:uuid` `serialNumber`, and accept
  `--serial-number` / `--bom-version` so a caller can express "this supersedes that".

## Out of scope

The 2026 document extends transparency considerations to AI systems and SaaS, with [AI SBOM
minimum elements](https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements)
as supplemental guidance covering models, datasets, performance indicators and AI-specific
infrastructure. None of that is in scope for a package-manifest scanner, and the guidance frames
it as additive to the general minimum elements rather than as part of them. The honest statement
is the limitation: a project that depends on model weights or datasets has those dependencies
invisible to this tool, and a `--components-only` SBOM will not say so.

SBOM *ingest* is likewise absent (already a documented known gap), which matters more under the
2026 framing than the 2021 one: the revision is explicitly oriented toward real-time
vulnerability management, and a tool that emits SBOMs but cannot consume one can only ever cover
half of that loop.

## Remediation, cheapest first

1. **Document-level metadata, no new data required** — `serialNumber`, `metadata.lifecycles`,
   drop the `0.0.0` fallback, `metadata.authors` from a new `--author` flag, an explicit unknown
   for Software Producer, primary-component version and purl. Confined to `report/cyclonedx.py`
   plus one flag. Closes §1, §12, most of §5 and "accommodation of updates".
2. **`compositions` and coverage disclosure** — stop emitting `dependsOn: []` for unknown
   parentage; declare `aggregate: incomplete`; carry `approximate`, `from_lockfile`,
   `scan_failed`, `skipped` and the active scope filter into the document. Closes §8 and §9, and
   this is the one item that fixes a defect rather than adding a feature. It should go first on
   merit even though it is second on cost.
3. **Component Hash** — a `hashes` field on `Dependency`, populated from data five parsers already
   see and discard, plus `go.sum` for Go. Closes §6 for five of seven ecosystems offline.
4. **License** — opt-in registry metadata, with Maven free from POMs already fetched. Closes §7.
   The largest change, because it introduces a network dependency on a path that has none.
5. **Software Producer, properly** — same registry work as (4), same call, so do them together.
6. **SPDX output** — only on demand.

Items 1–3 are self-contained and get the document from six of twelve fields to ten, with no new
network dependencies and no new false-clean risk.

## One caution on doing this work

Every field above adds a place where absence can be misread as absolution. An unknown license
rendered as blank reads as unencumbered; a missing hash reads as unverified-but-fine; a producer
of "unknown provenance" reads as trusted once it is one row among many in a table. The existing
safeguards — `None` distinct from empty, suppressed findings that stay in the report, tests that
assert the *absence* of reassuring strings — are the pattern to extend, not a precedent to work
around. Each new field wants its own negative test before it wants a renderer.
