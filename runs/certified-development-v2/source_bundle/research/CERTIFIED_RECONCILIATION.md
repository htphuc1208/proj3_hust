# Certified SBOM reconciliation V2

## Research question and status

When is the available, target-bound evidence sufficient to add or retract a
declared distribution dependency? V2 implements a conservative decision
procedure and executable certificates. Implementation/tests do not establish
novelty, empirical superiority, or acceptance at ICSE/FSE.

The development protocol is frozen in
[`configs/certified-reconciliation-v2.json`](../configs/certified-reconciliation-v2.json).
It uses old development roots only. The new 20/20/60 cohort is not consumed by
this experiment. Human audit and external tool comparisons remain explicit
uncompleted research tasks, not synthetic or LLM-generated achievements.

## Semantic contract

The graph covers the **declared direct requirements of installed Python
distributions in one explicit installation directory**. It does not describe
imports, executable contents or exploitability. Base requirements of every
installed distribution participate. Requested extra seeds are explicit; extras
propagate through requirements to a least fixed point. No-path remains UNKNOWN.

`ContextKnowledgeV2` uses nullable marker values and a separate
`root_requests_complete` flag. An omitted extra seed means no requested extra
only when this flag is true. Otherwise it is incomplete knowledge. This flag is
a trusted context assertion, not an inference from package presence or pip's
historical install flags. The development adapter preserves the existing
all-installed/base-declaration reference profile and states this in each job.

Evidence is bound to a target digest and physical `occurrence_path`, with native
SPDX CONTAINS/file locations or explicit CycloneDX metadata-path properties.
PURL equality alone cannot bind an occurrence. Multiple compatible installed
occurrences prevent unique endpoint resolution. Unread metadata cannot certify
that a visible compatible endpoint is unique. Registry evidence never acquires
target authority. Source/vendored records are retained outside this scope.

The observed document is defeasible, immutable evidence. It is not a set of hard
constraints: an explicit empty declaration may be contradicted and repaired in
a derived view. `SUPPORTED`, `REFUTED`, `UNKNOWN` and `CONFLICT` are separate.
Conflicting target evidence cannot authorize modifications.

## Rules and proof obligations

* `ACTIVE_DECLARATION`: a literal Requires-Dist citation, unique compatible
  physical child and a definitely true guard authorize add/keep.
* `NO_MATCHING_DECLARATION`: a fully parsed, supported-version installed parent
  METADATA and zero matching declarations authorize retraction in this scope.
* `ALL_MATCHING_DECLARATIONS_INACTIVE`: cite **all** matching declarations and
  prove every guard false. Extras-dependent negatives additionally require a
  checked upper activation invariant when the guard cannot otherwise be refuted.

Missing metadata, malformed requirements, old unsupported dependency fields,
unknown metadata completeness, unresolved URL/version binding and unknown
context do not become negative evidence. Installed `Dynamic` is informational;
sdist metadata is not accepted as installed evidence. The collector and context
author are part of the trust assumptions; SHA-256 proves byte binding, not truth.

The separate checker does not call the proposal generator or its fixed-point
construction. It verifies a finite lower derivation and checks that the supplied
upper invariant contains seeds and is closed under every possibly activating
requirement. Parsing, native indexing and conservative marker evaluation are
shared trusted code. Certificates are computational derivations, not
cryptographic attestations or proofs that the SBOM describes executed code.

### Soundness argument within the supported fragment

Assume the collector's target/inventory/location assertions and supplied context
are correct, the installed declarations are the intended relation, and parsing
and marker evaluation obey the stated semantics. Known extra seeds are in every
compatible completion. Induction on lower derivation steps preserves this
property. Each upper invariant contains the seeds and every possible propagation
step; induction on concrete fixed-point iterations bounds all actual extras.
Strong three-valued guard evaluation returns true/false only when every
compatible completion agrees. Unique target binding plus a true declaration
therefore supports an edge. Complete parent declarations plus zero matching or
all-false declarations refute it. An unread/ambiguous parent can prevent an upper
proof but cannot produce a false negative. These are relative soundness claims,
not completeness or whole-program soundness claims.

Local completeness is useful for no-matching declarations and platform-false
guards even when unrelated evidence is unread. In the all-installed graph an
unread parent may request another distribution's extra, so V2 conservatively
requires complete activation evidence for extras-dependent upper invariants.
It does **not** implement an unjustified optimization that calls such a parent
irrelevant based only on absent observed paths.

### Non-identifiability witness

Let A declare `B; extra == "opt"`. Install B independently, then compare requests
for A and A[opt]. The resulting inventory and METADATA can be identical while
the activated declared edge differs. If extra-request information is hidden,
neither an LLM nor a deterministic algorithm can identify the active graph from
that observation alone. V2 must abstain. The executable control tests this
knowledge distinction; it is not a real-world prevalence measurement.

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
observation bytes, derived SBOM, decisions/certificates, validation and a seal.
Invalid native candidates are named `candidate-invalid.json`. Old capture
timestamps remain capture metadata; new execution time is in the seal.
Legacy proposal contracts and recovery policies are unchanged.

## Development experiment and stopping rule

```bash
.venv/bin/python -B scripts/run_certified_development.py \
  --out runs/certified-development-v2
```

The runner requires the pinned Docker image and existing captures. It freezes
the dirty working-tree source, runner, configuration and protocol. Each of 20
old development roots has full evidence, controlled context withholding and
controlled 50% metadata withholding (source-ID ranking, seed 42). Unacquired
files and hidden legacy context are physically absent from worker mounts.
Workers have no network, target or oracle mount. The scorer verifies **all**
prediction seals before reading frozen references, then checks their input hashes
and pre-existing reference-manifest binding.

Observed, legacy additive/reconciliation, strong conservative metadata
interpretation and certified V2 are compared. The legacy context-unknown case is
explicitly unsupported and keeps its observation. The strong control shares
semantic primitives but uses direct interpretation, without certificates or the
proposal generator. A tie is an informative outcome, not an ablation failure to
be tuned away. Raw/native graph scores and changes remain separate; ambiguous
occurrences have unknown change labels under coordinate-level old references.

Co-primary outcomes are incorrect known changes / known changes and determinate
observed edges / observed native dependency edges. Whole-edge precision/recall/F1
are secondary. Unknown-change counts and optimistic/pessimistic risks are
reported. Null denominators remain null. Project-level bootstrap/randomization
uses 10,000 draws, 95% intervals and Holm correction for frozen contrasts. Shared
dependencies and selected single-environment roots limit independence. Review
packets select up to 40 add/retract/abstain tasks each; empty forms count as zero
human reviews. When fewer tasks exist, the shortfall is explicit.

If V2 ties the strong semantic control throughout complete development,
**do not run the new held-out cohort to claim accuracy superiority for V2**.
Preserve the result and reassess the scientific contribution of independently
checkable certificates. Completing code is not completing an A* publication.

## Literature and intended differences

| Source | Inheritance and limit |
| --- | --- |
| [Yu et al., DSN 2024](https://www.cs.ucr.edu/~heng/pubs/sbom-dsn24.pdf) | Differential scanner errors/parser patterns motivate controls; omissions alone are established. |
| [Cofano et al., TrustCom 2024](https://arxiv.org/abs/2409.01214) | Python versions, metadata and optional-dependency semantics motivate controlled cases. |
| [SIT, ICSE 2025 Demonstrations](https://doi.org/10.1109/ICSE-Companion66252.2025.00013) | Incremental construction/cross-validation are prior art; no first-repair claim. |
| [sbom-unifier, ICSME 2026 Tool Demonstrations](https://arxiv.org/abs/2608.30708) | Field complementation is distinct from edge correctness. |
| [SAP, TOSEM 2026](https://doi.org/10.1145/3788692) | Compliance, consistency and correctness require separate measurement and frozen tools. |
| [No Edges, No Verdict, preprint v4](https://arxiv.org/html/2607.22140v4) | Missing graph paths do not prove unreachable; existing edges also require checking. |
| [Reality Check, CODASPY 2026 v2](https://arxiv.org/html/2511.20313v2) | Package accuracy and downstream vulnerability applicability remain distinct. |
| [Libkin, Artificial Intelligence 2016](https://doi.org/10.1016/j.artint.2015.11.004) | Certain answers/possible worlds are foundations, not a new SBOM theorem. |
| [Razniewski & Nutt, PVLDB 2011](https://www.vldb.org/pvldb/vol4/p749-razniewski.pdf) | Query-local completeness inspires per-decision proof obligations. |

## Remaining research gates

Natural-case mechanism diversity and novelty need assessment against strong
controls; human audit is pending. CycloneDX Python environment, SIT and a new
scope-matched unifier comparison have not been run by this development runner.
Family verification, preregistration and frozen-method validation must precede
any new held-out study. Scientific claims about security impact, calibrated
coverage, multi-ecosystem generality and AI advantage are not made.
