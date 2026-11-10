# Evidence-based SBOM reconciliation V2

## Current behavior

The `reconcile` command directly evaluates installed declarations and writes a
derived SBOM plus a reason and metadata explanation for each assessed edge.
Certificate generation, certificate contracts and the separate certificate
checker have been removed. This changes the implementation; historical frozen
runs and their certificate-based results remain historical artifacts.

The graph covers declared direct requirements of installed Python distributions
in one explicit installation directory. Base requirements of every installed
distribution participate; requested extras propagate through requirements.
This does not establish runtime imports, executed code or exploitability.

`ContextKnowledgeV2` contains nullable marker values, `root_requests` and
`root_requests_complete`. Missing extra seeds mean no requested extras only
when the latter flag is true. Otherwise knowledge is incomplete. Context authors
and the metadata collector remain trusted sources of input assertions.

Evidence is bound to a target digest and physical metadata locations. PURL
equality alone does not bind a physical occurrence. Registry metadata does not
become evidence of a target installation. Missing or ambiguous metadata does not
justify negative conclusions. Unknown context is never filled from the host.

## Decision rules and explanations

- `ACTIVE_DECLARATION`: an installed Requires-Dist declaration, a unique compatible
  child and a definitely true condition support adding or keeping the edge.
- `NO_MATCHING_DECLARATION`: complete supported parent metadata with no matching
  declaration supports retracting an observed edge.
- `ALL_MATCHING_DECLARATIONS_INACTIVE`: every matching declaration must have a
  definitely false condition to retract an observed edge. Possible extra
  activation remains conservative when context or metadata is incomplete.
- `UNKNOWN` and `CONFLICT`: abstain; observed edges remain in the derived graph.

Each decision records `operation`, `status`, `reason` and `explanation`. For bound
endpoints, the explanation contains the parent evidence source ID, parent/child
metadata paths, parent completeness, known/possible parent extras and relevant
literal declarations with marker evaluation results (`true`, `false`, or `null`
for unknown). These are explanations, not independently checked proofs.
Input/context/evidence hashes remain recorded at result level for provenance.

The original observation remains immutable. Input/evidence integrity checks and
native SBOM format validation still run. Output uses policy
`evidence-reconciliation-v2` and schema `evidence-reconciliation-result-v2`;
there is no decision `certificate` or result `verification` field. Existing
Python callers can still use the compatibility name `reconcile_certified`, which
now calls `reconcile_evidence` without a certificate checker.

## CLI and evidence interface

Create a `reconciliation-context-v2` JSON with `target_id`,
`installation_scope` (for example `lib/python3.11/site-packages`),
`evidence_cutoff`, `marker_values`, `root_requests` and
`root_requests_complete`. Physical occurrence IDs are SHA-256 of the canonical
JSON `[target_id, occurrence_path]`. The trusted collector validates target_id
against `metadata_inventory(target)`; no old context is silently promoted to V2.

```bash
.venv/bin/python -B -m sbom_recovery reconcile-collect \
  --input observation.json --context context-v2.json --target /path/to/snapshot \
  --available-at 2026-11-09T00:00:00Z --out evidence-v2

.venv/bin/python -B -m sbom_recovery reconcile \
  --input observation.json --context context-v2.json \
  --evidence evidence-v2/manifest.json --out reconciliation-v2
```

The bundle has relative paths, exact byte sizes/hashes/times, acquisition flags,
inventory completeness and native-ref-to-occurrence bindings. All acquired files
are re-read through contained, non-symlink paths. Output contains the original
observation bytes, derived SBOM, decisions/explanations, validation and a seal.
Invalid native candidates are named `candidate-invalid.json`. Old capture
timestamps remain capture metadata; new execution time is in the seal.
Legacy proposal contracts and recovery policies are unchanged.

Replay a real, already staged development case without Docker or reference access:

```bash
.venv/bin/python -B -m sbom_recovery reconcile \
  --input runs/certified-development-v4/requests/full_metadata/input/observation.json \
  --context runs/certified-development-v4/requests/full_metadata/input/context.json \
  --evidence runs/certified-development-v4/requests/full_metadata/input/evidence/manifest.json \
  --out runs/certified-example-new
```

## Historical development artifacts

The [development findings](CERTIFIED_RECONCILIATION_FINDINGS_VI.md), frozen
`runs/certified-development-*` bundles, study configuration and recorded results
refer to the earlier certificate-based version. They have not been remeasured
for the current implementation. Historical runner method ID `certified_v2` is
retained for compatibility; current executions record the new policy in details.

The historical V2 tied its strong metadata control in 60/60 paired development
cases. No accuracy superiority, novelty, runtime exploitability or triage benefit
is established. Held-out evaluation and human audit remain uncompleted.

The development runner is available as an engineering regression comparison:

```bash
.venv/bin/python -B scripts/run_certified_development.py --out runs/reconciliation-development-new
```

It requires existing captures and the pinned Docker image. Current runs use the
current source snapshot; replay historical results from their frozen bundles.
