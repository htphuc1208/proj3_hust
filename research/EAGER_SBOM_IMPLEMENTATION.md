# Evidence-seeking SBOM investigation

The implementation lives in `sbom_recovery/investigation`. It connects the V3
multi-SBOM input contract to evidence acquisition, metadata and graph
reconciliation, an optional single investigation agent, standard-format exports,
and a separate evaluator. Existing Python V2 commands remain available.

## Run the controlled examples

```bash
.venv/bin/python -m sbom_recovery investigation demo --out /tmp/eager-examples
.venv/bin/python -m sbom_recovery investigation run \
  --request /tmp/eager-examples/npm/request.json \
  --policy rule --out /tmp/eager-npm \
  --snapshot /tmp/eager-examples/npm/advisories.json
.venv/bin/python -m sbom_recovery investigation score \
  --prediction /tmp/eager-npm/prediction.json \
  --oracle /tmp/eager-examples/npm/oracle/oracle.json \
  --out /tmp/eager-npm-score.json
.venv/bin/python -m sbom_recovery investigation study \
  --manifest /tmp/eager-examples/study.json --out /tmp/eager-study
# Expanded controls under both information regimes:
.venv/bin/python -m sbom_recovery investigation study \
  --manifest /tmp/eager-examples/study-baselines.json --out /tmp/eager-baselines
```

Output directories must be fresh. The examples deliberately contain conflicting
versions, reused native references, missing edges and an evidence source for the
wrong context. They are controlled npm/Cargo fixtures, with synthetic advisory
labels. They do not represent real scanner measurements or an independently
audited repository corpus.

## Input and evidence

`--request` uses `ReconciliationRequestV3`, documented by
`research/design/reconciliation-v3/schemas/input.schema.json`. Every input SBOM
and evidence source has a bundle-relative path and SHA-256. Native document
validation runs before inference. Document hashes namespace original refs.
Duplicate refs, dangling references, changed bytes, symlink paths and oracle
paths are rejected. Identical bytes are one observation even when two source
IDs name them.

Evidence is read only through the declared catalog. Native tool output has a
collection envelope:

```json
{
  "schema_version": "native-evidence-v1",
  "target": {
    "target_id": "release-1",
    "revision_ref": "frozen-revision",
    "context_id": "linux-runtime",
    "view": "RESOLVED"
  },
  "format": "npm-lock",
  "data": {"lockfileVersion": 3, "packages": {}}
}
```

Supported native collectors are npm lockfile v2/v3, npm logical-tree output and
Cargo metadata. `artifact_bytes` acquisition can hash the complete allowlisted
artifact and compare it with the target digest; a hash alone creates no component
or edge facts. Raw metadata files without a matching collection envelope do not acquire
target authority. A collected snapshot can also use
`schema_version: reconciliation-evidence-v1` with `components`, `edges` and
explicit `coverage` records. The runnable fixtures demonstrate the envelope and
request format.

Occurrence facts contain `occurrence_id`, ecosystem/name/version/PURL and an
optional `locator`. Edges reference occurrence IDs. Typed relations distinguish
`direct_dependency`, `contains` and `build_input_of`; a dependency `scope` keeps
runtime/development/build semantics. Coverage must explicitly declare a subject,
domain and `complete: true` before absence can refute an edge in that same scope.
Native collectors do not assume complete physical or shipped inventories.

Snapshot target labels are collection assumptions, not cryptographic build
attestations. The controller must audit their provenance. Registry facts are
candidate identities and cannot prove installed presence. Snapshot-supplied
observation bindings are ignored: the engine independently computes bindings.

## Reconciliation and uncertainty

The engine binds occurrences using compatible, evidence-backed locators. For
CycloneDX these come from `sbom-recovery:locator` properties or native occurrence
locations; SPDX can carry `sbom-recovery:locator=...` annotations. npm uses install
paths, including the empty root path. Cargo uses package manifest paths, while
native resolve-node IDs remain distinct.

An exact PURL can support an identity without establishing that two occurrences
are the same physical instance. Different versions or locators remain distinct
unless appropriate evidence resolves the ambiguity. Evidence-only packages may
be added with a supported target binding. Old assertions and optional native
fields remain in the provenance ledger even when a value is corrected.

Claims use `SUPPORTED`, `REFUTED`, `CONFLICT`, or `UNKNOWN`. Unsupported inferred
changes do not become verified facts. Observed unknown relationships retain
their observation status in the sidecar. Missing outgoing records never become
invented `dependsOn: []` records. No dependency path yields `UNKNOWN`.

Each run writes:

- `unified.spdx.json` and `unified.cdx.json`, with independent native validation;
- `prediction.json`, `evidence.json`, `conflict-report.json` and `dependency-graph.json`;
- `validation-report.json`, `tool-trace.json`, `transcript.json`, and `acquired-evidence.json`;
- `security-report.json` when a frozen OSV snapshot is supplied;
- `seal.json`, binding the actual output bytes and request digest.

SPDX 2.3 and CycloneDX 1.6 projections carry identities and typed relations.
Optional source metadata is preserved losslessly in the evidence sidecar rather
than silently selecting one producer's value. Format validation alone does not
establish semantic correctness.

## Investigation policies

`observed` preserves source assertions, `deterministic` collects sources in fixed
kind/order priority, and `rule` ranks unvisited descriptors using unresolved
subjects and source kinds. All inference uses the same deterministic evidence
rules. `--metadata-only` and `--graph-only` provide the A/B ablations.

`agent` asks a single model to choose one `acquire`, `inspect`, `match_advisories`, `verify`, or `finish` action
at a time and replans after the actual response. It sees catalog IDs and
descriptors, not filesystem paths or evaluation labels. `fixed_llm` disables
acquisition and uses only controller-provided evidence. A proposal must cite an
existing supported claim and evidence that supports that exact claim. The model
cannot authorize a package, version, edge, or safety conclusion by itself.

`--snapshot` exposes the same frozen public advisory data during investigation.
`--advisory CVE-ID` narrows the planning focus to an advisory ID or alias; the
model can call `match_advisories` before and after acquisition. Public affected
package/range metadata never includes the evaluator's target-specific labels.
Planning views contain bounded component/claim summaries and recent tool results.
`inspect` retrieves a selected component's native observations or another catalog
page, instead of resending all source SBOMs and provenance on every model turn.

For repeatable integration testing:

```bash
.venv/bin/python -m sbom_recovery investigation run \
  --request /tmp/eager-examples/npm/request.json --policy agent \
  --replay /tmp/eager-examples/npm/actions.json --out /tmp/eager-replay
```

These results are labeled `RECORDED_ACTION_REPLAY`, never live model results.
For live planning, set `NETMIND_API_KEY` in the environment and specify `--model`
plus a `--budget` JSON containing frozen input/output prices. The gateway uses
one HTTP attempt per planning step, timeouts, bounded response size, and strict
JSON actions. It stores model/version/fingerprint, usage and cost assumptions
without credentials. Tool attempts, including invalid or duplicate actions,
consume budget. Byte, step, time, model-call, token and monetary limits are
enforced. Unknown provider usage consumes the reserved maximum and ends the run.
Budget prices are experiment inputs, not provider billing verification.

## Evaluation boundaries

`score` is the only standalone command accepting an oracle. Predictions are
evaluated against a scope-matched `reconciliation-oracle-v1` reference. Missing
labels are not negatives; unknown labels and reference coverage are reported.
Candidate assertions and supported facts have separate component/edge/path
metrics, so scanner baselines do not receive automatic zero credit merely
because their observations are unverified. Field accuracy, incorrect corrections,
abstention coverage and labeled security outcomes are reported separately.

The offline OSV consumer holds advisory data and matching behavior fixed across
methods. Alias records are deduplicated. Exact-version and supported npm/Cargo
semantic-version ranges are evaluated; unsupported ranges stay unknown. A
package-level affected version and a supported dependency path are separate
outputs. Exploitability stays `NOT_ASSESSED`; non-match does not establish safety.

The study manifest freezes projects, lineages, splits, requests and oracle
digests. Project/lineage overlap across splits is rejected. Predictions are
sealed before labels are opened for scoring, with project-level paired bootstrap
support. Acquisition baselines compare equal budgets; equal-information studies
pass the same frozen facts to every method. Failed or unsupported cases must
remain visible. A pinned upstream `sbom-unifier` comparison uses the existing
native SPDX adapter; an unavailable or incompatible comparator must be reported
as unsupported, never replaced under its name.

Additional study methods are `naive_union`, `fixed_priority`, `majority`,
`lockfile_only` and `single:<source_id>`. Their choices, voting/source-order
assumptions and occurrence grouping remain explicit unverified observations.
The original comparator is named `sbom_unifier`; it calls the existing pinned
upstream implementation on native SPDX inputs.

The OSV matcher follows the published [evaluation algorithm](https://ossf.github.io/osv-schema/#evaluation).
Native collection boundaries follow the [npm lockfile format](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
and [Cargo metadata format and platform filtering](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).

An additional offline compatibility replay uses actual previously captured npm
and CycloneDX generator outputs, without opening any oracle:

```bash
.venv/bin/python -B scripts/run_investigation_generator_replay.py \
  --out /tmp/eager-generator-replay
```

## Evidence still needed for research conclusions

The code and controlled tests establish executable behavior. A real 20-project
pilot, natural-conflict adjudication, independent build inventories, frozen
generator outputs and prospective live-model comparisons are separate empirical
work. The previously inspected development corpus is not a fresh held-out set.
No correctness superiority, agent advantage, novelty, calibrated uncertainty or
exploitability result is established by this implementation. Multi-agent
coordination, full binary recovery, arbitrary repository builds and automatic
release-policy changes are outside the initial single-agent implementation.
