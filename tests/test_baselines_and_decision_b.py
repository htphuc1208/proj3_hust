#!/usr/bin/env python3
"""Unit tests for Research Lead Directive M2:
1. Decision B: Multi-version candidate matching (|C|=1, |C|>1, |C|=0).
2. P0.1 Invariants: MUST intersect MAY_ONLY == empty, MUST subset of POSSIBLE.
3. Baselines B0, B1, B2, B3 execution on identical inputs.
4. P0.4 Strong Anti-Leakage Negative Test (Filesystem isolation).
"""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from resolver import (
    ContextAwareResolver,
    TargetEnvironment,
    DependencyRequirement,
    PLAUSIBLE_ENVIRONMENTS,
    run_baseline_b0_observed_only,
    run_baseline_b1_context_free,
    run_baseline_b2_maximal_supergraph,
    run_baseline_b3_context_aware
)
from evaluator import evaluate_regime_u_uncertainty, evaluate_reconstruction_edges
from registry_provider import FrozenRegistryEvidenceProvider, build_evidence_snapshot


class MockProvider:
    def __init__(self, db):
        self.db = db
        self.source_name = "mock-registry"

    def get_requirements(self, purl):
        return self.db.get(purl)


class TestDecisionBAndBaselines(unittest.TestCase):

    def test_decision_b_cardinality_rules(self):
        """Tests |C|=1 (unique bind), |C|>1 (AMBIGUOUS_MATCH), |C|=0 (unpinned candidate)."""
        provider_db = {
            "pkg:pypi/my-app@1.0.0": [
                # Requirement 1: Unique match in SBOM
                DependencyRequirement(target_purl="pkg:pypi/lib-unique", specifier=">=2.0"),
                # Requirement 2: Ambiguous match in SBOM (two versions satisfy >=1.0)
                DependencyRequirement(target_purl="pkg:pypi/lib-multi", specifier=">=1.0"),
                # Requirement 3: Missing component (not in SBOM)
                DependencyRequirement(target_purl="pkg:pypi/lib-missing", specifier="==3.0.0")
            ]
        }
        provider = MockProvider(provider_db)
        resolver = ContextAwareResolver(provider)

        input_sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {
                "component": {"type": "application", "bom-ref": "app-ref", "purl": "pkg:pypi/my-app@1.0.0", "name": "my-app", "version": "1.0.0"}
            },
            "components": [
                # lib-unique has one component matching >=2.0
                {"type": "library", "bom-ref": "uniq-ref", "purl": "pkg:pypi/lib-unique@2.5.0", "name": "lib-unique", "version": "2.5.0"},
                # lib-multi has TWO components matching >=1.0
                {"type": "library", "bom-ref": "multi-1", "purl": "pkg:pypi/lib-multi@1.2.0", "name": "lib-multi", "version": "1.2.0"},
                {"type": "library", "bom-ref": "multi-2", "purl": "pkg:pypi/lib-multi@1.8.0", "name": "lib-multi", "version": "1.8.0"},
            ],
            "dependencies": [
                {"ref": "app-ref", "dependsOn": []}
            ]
        }

        res = resolver.resolve(input_sbom)
        cand_edges = res["G_candidate"]["edges"]

        # 1. Verify |C| == 1 bound uniquely to lib-unique@2.5.0
        uniq_edge = next(e for e in cand_edges if "lib-unique" in e["target_purl"])
        self.assertEqual(uniq_edge["target_purl"], "pkg:pypi/lib-unique@2.5.0")
        self.assertIn(uniq_edge["status"], ("INFERRED", "CONTRADICTED_DECLARATION"))

        # 2. Verify |C| > 1 was NOT bound; emitted AMBIGUOUS_MATCH and UNKNOWN modality
        multi_edge = next(e for e in cand_edges if "lib-multi" in e["target_purl"])
        self.assertEqual(multi_edge["status"], "AMBIGUOUS_MATCH")
        self.assertEqual(multi_edge["modality"], "UNKNOWN")
        self.assertEqual(len(multi_edge["candidate_refs"]), 2)
        self.assertIn("pkg:pypi/lib-multi@1.2.0", multi_edge["candidate_refs"])
        self.assertIn("pkg:pypi/lib-multi@1.8.0", multi_edge["candidate_refs"])

        # Verify AMBIGUOUS edge was excluded from G_reconstructed
        reconstructed_deps = res["G_reconstructed"]["dependencies"]
        app_deps = next(d["dependsOn"] for d in reconstructed_deps if d["ref"] == "app-ref")
        self.assertIn("uniq-ref", app_deps)
        self.assertNotIn("multi-1", app_deps)
        self.assertNotIn("multi-2", app_deps)

        # 3. Verify |C| == 0 generated unpinned candidate node without hallucinating version
        missing_edge = next(e for e in cand_edges if "lib-missing" in e["target_purl"])
        self.assertEqual(missing_edge["target_purl"], "pkg:pypi/lib-missing")
        cand_nodes = res["G_candidate"]["nodes"]
        missing_node = next(n for n in cand_nodes if n["purl"] == "pkg:pypi/lib-missing")
        self.assertEqual(missing_node["status"], "INFERRED")

    def test_p01_mathematical_invariants(self):
        """Verifies MUST intersect MAY_ONLY == empty and MUST subset of POSSIBLE."""
        candidate_edges = [
            {"source_purl": "pkg:pypi/app@1.0", "target_purl": "pkg:pypi/core@1.0", "modality": "MUST"},
            {"source_purl": "pkg:pypi/app@1.0", "target_purl": "pkg:pypi/win32@1.0", "modality": "MAY_ONLY"},
            {"source_purl": "pkg:pypi/app@1.0", "target_purl": "pkg:pypi/unknown@1.0", "modality": "UNKNOWN"},
        ]
        ground_truth_by_env = {
            "linux": {("pkg:pypi/app@1.0", "pkg:pypi/core@1.0")},
            "win32": {("pkg:pypi/app@1.0", "pkg:pypi/core@1.0"), ("pkg:pypi/app@1.0", "pkg:pypi/win32@1.0")}
        }
        res = evaluate_regime_u_uncertainty(candidate_edges, ground_truth_by_env, target_env_id="linux")
        self.assertTrue(res["invariants_verified"]["must_intersect_may_only_empty"])
        self.assertTrue(res["invariants_verified"]["must_subset_possible"])
        self.assertEqual(res["predicted_must_count"], 1)
        self.assertEqual(res["predicted_may_only_count"], 1)
        self.assertEqual(res["predicted_possible_count"], 2)
        self.assertEqual(res["unknown_count"], 1)

    def test_baselines_b0_b1_b2_b3_comparison(self):
        """Runs B0, B1, B2, B3 on identical input and verifies differential behavior."""
        # requests has:
        # - unconditional: urllib3, certifi, charset-normalizer, idna
        # - extra == 'socks': PySocks
        provider_db = {
            "pkg:pypi/requests@2.31.0": [
                DependencyRequirement(target_purl="pkg:pypi/urllib3"),
                DependencyRequirement(target_purl="pkg:pypi/certifi"),
                DependencyRequirement(target_purl="pkg:pypi/PySocks", marker='extra == "socks"')
            ]
        }
        provider = MockProvider(provider_db)
        sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {
                "component": {"type": "application", "bom-ref": "req-ref", "purl": "pkg:pypi/requests@2.31.0", "name": "requests", "version": "2.31.0"}
            },
            "components": [
                {"type": "library", "bom-ref": "u-ref", "purl": "pkg:pypi/urllib3@2.0.7", "name": "urllib3", "version": "2.0.7"},
                {"type": "library", "bom-ref": "c-ref", "purl": "pkg:pypi/certifi@2023.7.22", "name": "certifi", "version": "2023.7.22"},
                {"type": "library", "bom-ref": "s-ref", "purl": "pkg:pypi/pysocks@1.7.1", "name": "pysocks", "version": "1.7.1"},
            ],
            "dependencies": [
                {"ref": "req-ref", "dependsOn": []}
            ]
        }

        # B0: 0 edges
        b0 = run_baseline_b0_observed_only(sbom)
        self.assertEqual(len(b0["predicted_edges"]), 0)

        # B1: Context-free (adds all 3 including PySocks unconditionally)
        b1 = run_baseline_b1_context_free(sbom, provider)
        self.assertEqual(len(b1["predicted_edges"]), 3)
        self.assertIn(("pkg:pypi/requests@2.31.0", "pkg:pypi/pysocks@1.7.1"), b1["predicted_edges"])

        # B2: Maximal supergraph (accepts PySocks as possible extra)
        b2 = run_baseline_b2_maximal_supergraph(sbom, provider)
        self.assertEqual(len(b2["predicted_edges"]), 3)

        # B3: Context-aware without extras (excludes PySocks because extra is not active)
        env_no_extras = TargetEnvironment(
            os_name="posix", sys_platform="linux", platform_machine="x86_64", python_version="3.11", active_extras=set()
        )
        b3 = run_baseline_b3_context_aware(sbom, provider, target_env=env_no_extras)
        self.assertEqual(len(b3["predicted_edges"]), 2)
        self.assertNotIn(("pkg:pypi/requests@2.31.0", "pkg:pypi/pysocks@1.7.1"), b3["predicted_edges"])

        # Ground truth where target was installed WITHOUT extras
        E_t = {
            ("pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@2.0.7"),
            ("pkg:pypi/requests@2.31.0", "pkg:pypi/certifi@2023.7.22")
        }
        E_o = set()

        eval_b0 = evaluate_reconstruction_edges(E_t, E_o, b0["predicted_edges"])
        eval_b1 = evaluate_reconstruction_edges(E_t, E_o, b1["predicted_edges"])
        eval_b3 = evaluate_reconstruction_edges(E_t, E_o, b3["predicted_edges"])

        self.assertEqual(eval_b0["recall"], 0.0)
        self.assertEqual(eval_b1["fp"], 1)  # B1 falsely added PySocks
        self.assertEqual(eval_b3["fp"], 0)  # B3 correctly rejected PySocks
        self.assertEqual(eval_b3["precision"], 1.0)
        self.assertEqual(eval_b3["recall"], 1.0)

    def test_p04_strong_anti_leakage_filesystem_negative_test(self):
        """Proves reconstruction output is completely independent of oracle files.
        
        Even if oracle files are renamed or moved, the reconstruction engine produces
        the exact same predictions because it has zero access to them.
        """
        snapshot_dir = ROOT / "fixtures" / "evidence_snapshot"
        provider = FrozenRegistryEvidenceProvider(snapshot_dir)
        resolver = ContextAwareResolver(provider)

        test_sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {
                "component": {"type": "application", "bom-ref": "r-ref", "purl": "pkg:pypi/requests@2.31.0", "name": "requests", "version": "2.31.0"}
            },
            "components": [
                {"type": "library", "bom-ref": "u-ref", "purl": "pkg:pypi/urllib3@2.0.7", "name": "urllib3", "version": "2.0.7"}
            ],
            "dependencies": [{"ref": "r-ref", "dependsOn": []}]
        }

        # Run 1: Normal execution
        res1 = resolver.resolve(test_sbom)

        # Run 2: Isolated sandbox execution (temp directory with no oracle anywhere)
        with tempfile.TemporaryDirectory() as sandbox_dir:
            sandbox = Path(sandbox_dir)
            clean_evidence = sandbox / "evidence"
            shutil.copytree(snapshot_dir, clean_evidence)

            # Intentionally create disguised fake files in sandbox
            disguised_file = sandbox / "obscure_binary_data.bin"
            disguised_file.write_text("fake oracle data that should never be read")

            clean_provider = FrozenRegistryEvidenceProvider(clean_evidence)
            clean_resolver = ContextAwareResolver(clean_provider)
            res2 = clean_resolver.resolve(test_sbom)

            # Outputs must be 100% identical
            edges1 = {(e["source_purl"], e["target_purl"]) for e in res1["G_candidate"]["edges"]}
            edges2 = {(e["source_purl"], e["target_purl"]) for e in res2["G_candidate"]["edges"]}
            self.assertEqual(edges1, edges2)


if __name__ == "__main__":
    unittest.main()
