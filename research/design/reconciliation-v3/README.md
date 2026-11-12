# A+B+E V3 design contracts

Primary design: [problem](../../../PROBLEM_FORMULATION.md),
[architecture](../../../ARCHITECTURE.md), [milestones](../../RECONCILIATION_PLAN_V3.md).
The module provides a draft multi-SBOM request, not an alignment/merge engine.

The two synthetic input SBOMs reuse native ref `dependency`, but report different
versions. Their byte hashes are recorded in input.json. Both documents remain
intact. There is deliberately **no expected merged winner**: the data does not
establish whether a tool is wrong or two actual instances/versions coexist.

Request labels identify the intended comparison group. They do not prove
same-build provenance. Missing context/revision/view information stays missing;
the future scope binder must decide admissibility. Inputs with explicitly
different scopes must be sent to separate groups.

Artifact evidence is optional. The earlier
[artifact contracts](../artifact-reconciliation-v3/README.md) describe only that
subtask and are not required for every multi-SBOM input.

```bash
.venv/bin/python -B scripts/export_reconciliation_design_v3.py
.venv/bin/python -B -m unittest tests.test_merge_contracts_v3 -v
```

Schema/model validation does not read or hash the real inputs, execute a
scanner, resolve components, infer edges or validate vulnerability findings.
