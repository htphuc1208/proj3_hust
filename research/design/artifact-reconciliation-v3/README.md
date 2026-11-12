# V3 design contracts

This is the optional artifact-evidence adapter draft. The primary direction is
now **A+B+E multi-SBOM reconciliation**; an artifact is not mandatory for that
request. Earlier artifact-only [formulation](formulation.md),
[architecture](architecture.md) and [roadmap](roadmap.md) are retained as design
history and adapter reference.

These are draft wire contracts and **synthetic examples**, not measured repairs
or a working artifact-reconciliation CLI. The example artifact paths and SHA-256
values are placeholders. Models validate data shape and selected boundaries;
they do not read those files, verify their bytes, establish trust or run inference.

The [problem](../../../PROBLEM_FORMULATION.md), [architecture](../../../ARCHITECTURE.md)
and [milestones](../../RECONCILIATION_PLAN_V3.md) define the proposed system.

| Example | Intended behavior |
| --- | --- |
| input.json | Partial context; [] means known-empty, null means unknown; supplied evidence cannot self-assign a binding |
| supported-component.assessment.json | Hypothetical bound identity/metadata permit a component addition; no dependency edge is invented |
| metadata-only.assessment.json | Selected for build and no code footprint can coexist; no component deletion or advisory suppression |
| ambiguous-identity.assessment.json | Shared/partial fingerprint keeps multiple candidates and defers the proposed change |
| conflicting-identity.assessment.json | Conflicting observations of the same identity claim defer the proposed change |

Regenerate the schemas/examples from the data models:

```bash
.venv/bin/python -B scripts/export_artifact_design_v3.py
.venv/bin/python -B -m unittest tests.test_artifact_contracts_v3 -v
```

JSON Schema covers structural constraints. The Pydantic models also check
references, polarity/status, scope, binding resolution and selected operation
preconditions. Neither replaces the future evidence-admission rules, filesystem
loader, identity inference or exporter. Passing a contract does not prove that a
supplier's or collector's assertions are true.
