# ARCHITECTURE SPECIFICATION: Context-Aware, Evidence-Guided SBOM Reconstruction Under Uncertainty

**Author:** Master's Thesis Research Initiative  
**Methodological Standard:** A* Senior Researcher / Tier-1 Venue Alignment (IEEE S&P, ACM CCS, USENIX Security, ICSE, FSE)  
**Scope:** CycloneDX (OWASP/ECMA), PEP 508 Markers, Python/PyPI Ecosystem, OpenVEX, OSV

---

## 1. Formal Problem Formulation

Let an application deployment in environment $E \in \mathcal{E}$ have a true installed distribution graph:
$$G^*_E = (V^*_E, E^*_E, \mu^*_E)$$
where:
* $V^*_E$: Set of verified installed distribution packages.
* $E^*_E$: Directed edges $(u, v)$ where package $u$ requires package $v$ under environment $E$.
* $\mu^*_E$: Metadata mapping for nodes and edges (version, provenance, hashes, license).
* $E = (\text{os}, \text{arch}, \text{python\_version}, \text{platform\_release}, \text{active\_extras})$.

The observed SBOM is an imperfect, potentially incomplete and contradictory subgraph:
$$G_{\text{obs}} = (V_{\text{obs}}, E_{\text{obs}}) \not\subseteq G^*_E$$

Given external evidence $M$ (Package distribution metadata, wheel `Requires-Dist`, registry feeds), the reconstruction task is to learn or compute an estimator:
$$\hat{G}_E = R(G_{\text{obs}}, E, M)$$

### Missing Environment Context Formulation
When the execution environment $E$ is omitted from the input:
$$\mathcal{E}_{\text{plausible}} = \{e_1, e_2, \dots, e_k\}$$
Edges are partitioned into epistemic modalities:
* **MUST Edges ($E_{\text{must}}$):** Invariant across all plausible environments:
  $$E_{\text{must}} = \bigcap_{e \in \mathcal{E}_{\text{plausible}}} E(\hat{G}_e)$$
* **MAY Edges ($E_{\text{may}}$):** Environment-conditional edges:
  $$E_{\text{may}} = \bigcup_{e \in \mathcal{E}_{\text{plausible}}} E(\hat{G}_e) \setminus E_{\text{must}}$$
* **UNKNOWN Edges / Nodes:** Insufficient metadata, unresolvable version constraints, or missing distribution artifacts.

---

## 2. Multi-Tier Graph Model & Contradiction Detection

To preserve auditability and provenance, the original observed SBOM is **immutable**. The system maintains three distinct graph structures:

1. **Observed Graph ($G_{\text{obs}}$):** The verbatim input parsed from CycloneDX.
2. **Candidate Hypothesis Graph ($G_{\text{candidate}}$):** Inferred nodes and edges equipped with evidence provenance:
   $$e = (u, v, \text{evidence}, \text{context}, \text{status})$$
3. **Reconstructed Graph ($G_{\text{reconstructed}}$):** Synthesized target graph $R(G_{\text{obs}}, G_{\text{candidate}}, \text{Evidence})$.

### Contradiction Detection Semantics (CycloneDX Compliance)
* In CycloneDX, `dependsOn: []` denotes an explicit declaration of zero direct dependencies.
* An omitted dependency record denotes unknown status.
* When external artifact metadata demonstrates that $u \to v$ is mandatory under $E$, but $G_{\text{obs}}$ declares `u.dependsOn: []`, the system **does not silently overwrite** $G_{\text{obs}}$. Instead, it flags:
  $$\text{Status} = \texttt{CONTRADICTED\_DECLARATION}$$
  accompanied by artifact hash, marker evaluation trace, and candidate repair action.

### Evidence Policy Matrix

| Condition | Observed SBOM | Evidence Source | Action & Output Status |
| :--- | :--- | :--- | :--- |
| **P1** | No dependency record for $u$ | Artifact metadata satisfies $E$ | Incur Candidate Edge (`STATUS_INFERRED`) |
| **P2** | $u$ declares `dependsOn: []` | Installed artifact metadata satisfies $E$ | Emit Contradiction Warning + Repair Candidate (`CONTRADICTED_DECLARATION`) |
| **P3** | `compositions.aggregate = complete` | Evidence demonstrates missing edge | Flag Inconsistency Violation; do not silently bypass |
| **P4** | Dependency conditioned on marker | Marker true in subset of $\mathcal{E}$ | Classify edge as `MAY` with conditional predicate |
| **P5** | Ambiguous version / missing distribution | No verifiable artifact | Mark as `UNKNOWN` (Abstain from prediction) |

---

## 3. Ground Truth Protocol & Anti-Leakage Isolation

### Ground Truth Derivation Pipeline
1. **Target Environment Build:** Dedicated container running exact OS, architecture, and Python runtime.
2. **Pinned Installation:** Execute `pip install --report report.json <project>` with explicit target extras.
3. **Distribution Metadata Extraction:** Parse installed distribution `METADATA` / `RECORD` / `Requires-Dist`.
4. **Context Evaluation:** Evaluate `Requires-Dist` against active environment tuple $E$.
5. **Cross-Validation:** Cross-check with `pip check` and `pipdeptree`.

### Anti-Leakage Safeguards
* **Input Isolation:** The reconstruction engine operates strictly on degraded SBOMs and public registry metadata. It is completely blinded to the build report and installed environment filesystem.
* **Partitioning:** Benchmark splits are performed strictly at the **Project level**, with temporal hold-outs for package release timestamps where applicable.

---

## 4. Reachability & Security Triage Formalism

### Level 1: Dependency Graph Path Reachability
* Path existence: $u \rightsquigarrow v$ in $\hat{G}_E$.
* Metric: **Vulnerability Recovery Rate (VRR)**:
  $$\text{VRR} = \frac{|\mathcal{V}_{\text{vuln}} \cap \text{Reachable}(\hat{G}_E)|}{|\mathcal{V}_{\text{vuln}} \cap \text{Reachable}(G^*_E)|}$$
* OpenVEX Compliance: An absence of path in $\hat{G}_E$ never implies `not_affected`. The status remains `under_investigation` unless verified by a formal non-reachability assertion.

### Level 2: Function-Level Reachability
* Static call paths are treated as conservative heuristics.
* Any lack of inter-procedural path is marked `UNKNOWN`, never `PROVEN_UNREACHABLE`.

---

## 5. Research Questions (RQs)

* **RQ1 (Reconstruction Accuracy):** How accurately do environment-constrained rules recover missing nodes and edges compared to context-free baselines across synthetic and in-the-wild generator omissions?
* **RQ2 (Value of AI):** Under ambiguous or contradictory evidence, does constrained machine learning ranking (e.g., LightGBM / XGBoost) improve calibrated precision-recall and reduce selective risk over optimal heuristic resolvers?
* **RQ3 (Downstream Security Utility):** What is the net delta in vulnerable dependency path discovery (VRR) and false positive triage burden when transitioning from unaugmented SBOMs to reconstructed candidate graphs?
