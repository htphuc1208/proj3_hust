# SBOM Reconciliation for Vulnerability Matching

Current implementation: evidence-guided reconstruction of installed Python SBOM dependency graphs. The V3 design combines metadata correctness (A), dependency-graph reconciliation (B) and downstream vulnerability evaluation (E) across multiple SBOMs. Artifact evidence is optional.

See the [V3 problem formulation](PROBLEM_FORMULATION.md), [architecture](ARCHITECTURE.md)
and [implementation milestones](research/RECONCILIATION_PLAN_V3.md).
V3 currently provides design/input contracts and optional artifact contracts;
the multi-SBOM alignment/reconciliation pipeline is not implemented. Existing CLI
examples below use Python V2.
Accuracy superiority and research novelty are not established.

---

## Key Capabilities

1. **Context-Aware Dependency Resolution (PEP 508):**
   - Evaluates dependency specifiers and environment markers across targeted or multi-context environments (`Linux`, `Windows`, `Darwin` × `Python 3.10-3.12`).
   - Strict Epistemic Modality: classifies inferred edges into `MUST`, `MAY_ONLY`, or `UNKNOWN`.
   - Decision B Cardinality: handles unique bindings ($|C|=1$), ambiguous matches ($|C|>1$), and unpinned candidates ($|C|=0$) with explicit `CONTRADICTED_DECLARATION` detection.
   - Preserves $G_{\text{obs}}$ immutable while deriving $G_{\text{candidate}}$ and $G_{\text{reconstructed}}$.

2. **Downstream Security Reachability Hierarchy:**
   - **Level 0:** Package co-occurrence in SBOM.
   - **Level 1:** Dependency graph path $u \rightsquigarrow v$ (recovered via graph reconstruction).
   - **Level 2:** Static call-graph reachability (inter-procedural AST call paths). Finding no path means **`UNKNOWN` / `NOT_OBSERVED`**, never `SAFE`.
   - **Level 3:** Dynamic runtime exploitability.

3. **Lossless Multi-Format Normalization:**
   - CycloneDX 1.5/1.6/1.7 and SPDX 2.3 support.
   - PURL normalization adhering to PEP 503 and packageurl-python specifications.

---

## Quickstart

### 1. Interactive Web Interface & Visualizer
To launch the interactive dashboard and reachability visualizer:

```bash
./.venv/bin/python ui/server.py 8088
```

Open <http://localhost:8088> in your browser to inspect reconstructed graphs, compare scanner outputs, and analyze vulnerability reachability.

### 2. Offline Demonstration (Pure Standard Library)
Run the baseline offline demonstration (requires only standard Python 3.9+, no pip dependencies):

```bash
# Run without source code (Level 1 dependency path only)
./.venv/bin/python poc.py --out results/no_source

# Run with source code (Level 1 + Level 2 static call-graph reachability)
./.venv/bin/python poc.py --source demo_source --out results/with_source
```

Open `results/with_source/dashboard.html` in your browser to toggle between the original and reconstructed SBOM graphs.

### 3. Running All Tests
To execute the automated unit tests covering resolvers, baselines, temporal protocols, and validators:

```bash
./scripts/run_all_tests.sh
```

Or directly via unittest:

```bash
./.venv/bin/python -m unittest discover -s tests -v
```

---

## Evidence-based reconciliation V2

The `reconcile-collect` and `reconcile` commands bind installed metadata to
physical occurrences, represent unknown context explicitly, and directly apply
semantic rules to add or retract declared dependency edges. Each decision has a
reason and metadata explanation in `assessment.json`. Certificate generation and
the separate certificate checker have been removed from the current flow.
Native SBOM validation and input/evidence integrity checks still run.

See the [CLI guide](research/CERTIFIED_RECONCILIATION.md).
The [development findings](research/CERTIFIED_RECONCILIATION_FINDINGS_VI.md) and
[development report](runs/certified-development-v4/REPORT.md) describe the earlier
certificate-based implementation, not new measurements of the current flow.
That historical version tied the strong semantic control in all 60 paired cases;
accuracy superiority and A* novelty are not established.

The agent branch checks proposals against evidence and output-validation rules.
Conformal fitting and abstention, the `calibrate` / `calibration-decisions`
commands and benchmark `--calibration` option have been removed. Decisions may
still remain unknown when evidence is insufficient. Historical frozen runs keep
their original artifacts; new study plans use `agent-study-v3-no-conformal`.

## Core Architecture & Module Map

| Component | Source File | Description | Relevant Tests |
| :--- | :--- | :--- | :--- |
| **Formal Resolver** | `resolver.py` | Context-aware resolution, Decision B cardinality, baselines B0–B3 | `tests/test_milestone1.py`, `tests/test_baselines_and_decision_b.py` |
| **Research Core** | `research_core.py` | Normalization, scope audits, CycloneDX schema validation, RunBundle | `tests/test_validation.py`, `tests/test_experiment.py` |
| **Registry Evidence** | `registry_provider.py` | Frozen package metadata provider and evidence snapshot loading | `tests/test_registry_provider.py` |
| **Recovery Package** | `sbom_recovery/` | Ground-truth contracts, claim ledgers, reachability, and reconciliation | `tests/test_gold_builder.py`, `tests/test_paired_reconciliation.py` |
| **Interactive UI** | `ui/` | Web server, reachability API, and front-end visualization | `tests/test_budget_ui.py`, `tests/test_reachability_api.py` |
| **Baseline PoC** | `poc.py`, `dashboard.py` | Minimal standalone demonstration with standard library | `tests/test_poc.py` |

---

## Scientific Principles & Invariants

Research boundaries are recorded in the [V3 problem formulation](PROBLEM_FORMULATION.md)
and the [historical Python protocol](research/PROTOCOL.md). The Python implementation follows these invariants:
- **Fail-Closed Principle:** Absence of evidence is not evidence of absence. Missing dependency or call paths must be labeled `UNKNOWN` or `NOT_OBSERVED`, never `SAFE` or `PROVEN_UNREACHABLE`.
- **Anti-Data / Anti-Label Leakage:** Ground truth oracle is strictly isolated and used only for evaluation scoring (`research_core.score_application`). Ground truth never leaks into candidate generation.
- **Candidate Discipline:** Inferred packages and edges remain *candidates*; they are never conflated with verified installed packages without explicit physical installation evidence.
- **Epistemic Modality:** Environmental uncertainty requires conditional reasoning $P(e \mid \mathcal{E})$; unsupported assumptions are rejected.
