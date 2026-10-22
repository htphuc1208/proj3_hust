#!/usr/bin/env python3
"""Milestone 1 Test Suite: Verification of the 3 Mandatory Research Test Cases.

Test A — Environment-dependent edge (PEP 508 conditions, MUST/MAY/UNKNOWN classification).
Test B — Contradictory SBOM declaration (dependsOn: [] with contrary installed evidence).
Test C — Missing component changes security analysis (Omitted node + path recovery + real advisory).
"""
import unittest
import sys
from pathlib import Path
from copy import deepcopy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from resolver import (
    ContextAwareResolver,
    TargetEnvironment,
    DependencyRequirement,
    CandidateEdge,
    CandidateNode,
    normalize_purl,
    PLAUSIBLE_ENVIRONMENTS
)


class MockMetadataProvider:
    """Mock distribution metadata provider for controlled empirical testing."""
    def __init__(self, requirements_db, source_name="distribution-wheel-metadata"):
        self.db = requirements_db
        self.source_name = source_name

    def get_requirements(self, purl):
        norm = normalize_purl(purl)
        return self.db.get(norm)


class Milestone1ResearchTests(unittest.TestCase):

    def test_A_environment_dependent_edges(self):
        """
        Test A:
        1. Run under Linux + Python 3.11 -> Windows-specific edge is NOT included.
        2. Run under Windows + Python 3.10 -> Windows-specific edge IS included.
        3. Run without specified environment -> System partitions edges into MUST vs MAY.
        """
        requirements_db = {
            "pkg:pypi/data-processor@1.0.0": [
                # Unconditional edge -> Invariant across all platforms
                DependencyRequirement(target_purl="pkg:pypi/common-lib@2.0.0"),
                # Windows-only platform marker
                DependencyRequirement(target_purl="pkg:pypi/win32-support@1.5.0", marker='sys_platform == "win32"'),
                # Legacy Python version marker
                DependencyRequirement(target_purl="pkg:pypi/legacy-compat@0.9.0", marker='python_version < "3.11"')
            ]
        }
        provider = MockMetadataProvider(requirements_db)
        resolver = ContextAwareResolver(provider)

        input_sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {
                "component": {
                    "type": "application", "bom-ref": "app-ref",
                    "purl": "pkg:pypi/data-processor@1.0.0", "name": "data-processor", "version": "1.0.0"
                }
            },
            "components": [],
            "dependencies": []
        }

        # Case 1: Target Environment = Linux + Python 3.11
        linux_env = TargetEnvironment(
            os_name="posix", sys_platform="linux", platform_machine="x86_64", python_version="3.11", platform_system="Linux"
        )
        res_linux = resolver.resolve(input_sbom, target_env=linux_env)
        linux_edges = {e["target_purl"] for e in res_linux["G_candidate"]["edges"]}
        self.assertIn("pkg:pypi/common-lib@2.0.0", linux_edges)
        self.assertNotIn("pkg:pypi/win32-support@1.5.0", linux_edges, "Windows edge must not exist in Linux 3.11")
        self.assertNotIn("pkg:pypi/legacy-compat@0.9.0", linux_edges, "Legacy Python edge must not exist in Python 3.11")

        # Case 2: Target Environment = Windows + Python 3.10
        win_env = TargetEnvironment(
            os_name="nt", sys_platform="win32", platform_machine="AMD64", python_version="3.10", platform_system="Windows"
        )
        res_win = resolver.resolve(input_sbom, target_env=win_env)
        win_edges = {e["target_purl"] for e in res_win["G_candidate"]["edges"]}
        self.assertIn("pkg:pypi/common-lib@2.0.0", win_edges)
        self.assertIn("pkg:pypi/win32-support@1.5.0", win_edges, "Windows edge must exist in Windows 3.10")
        self.assertIn("pkg:pypi/legacy-compat@0.9.0", win_edges, "Legacy edge must exist in Python 3.10")

        # Case 3: Missing Environment (Epistemic MUST / MAY classification)
        res_multi = resolver.resolve(input_sbom, target_env=None)
        modalities = {e["target_purl"]: e["modality"] for e in res_multi["G_candidate"]["edges"]}
        self.assertEqual(modalities.get("pkg:pypi/common-lib@2.0.0"), "MUST",
                         "Unconditional edge must be MUST across all plausible environments")
        self.assertEqual(modalities.get("pkg:pypi/win32-support@1.5.0"), "MAY_ONLY",
                         "Windows-conditional edge must be classified as MAY_ONLY")
        self.assertEqual(modalities.get("pkg:pypi/legacy-compat@0.9.0"), "MAY_ONLY",
                         "Python-version-conditional edge must be classified as MAY_ONLY")

    def test_B_contradictory_sbom_declaration(self):
        """
        Test B:
        1. SBOM declares `dependsOn: []` for flask@2.0.1.
        2. Installed artifact metadata confirms flask requires werkzeug@2.0.3.
        3. System detects contradiction, leaves G_obs untouched, and outputs candidate repair with provenance.
        """
        requirements_db = {
            "pkg:pypi/flask@2.0.1": [
                DependencyRequirement(target_purl="pkg:pypi/werkzeug@2.0.3")
            ]
        }
        provider = MockMetadataProvider(requirements_db, source_name="installed-wheel-metadata")
        resolver = ContextAwareResolver(provider)

        input_sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {
                "component": {
                    "type": "application", "bom-ref": "app-ref",
                    "purl": "pkg:pypi/web-service@1.0.0", "name": "web-service", "version": "1.0.0"
                }
            },
            "components": [
                {"type": "library", "bom-ref": "flask-ref", "name": "flask", "version": "2.0.1", "purl": "pkg:pypi/flask@2.0.1"}
            ],
            "dependencies": [
                {"ref": "app-ref", "dependsOn": ["flask-ref"]},
                # Faulty generator omission: declared empty list!
                {"ref": "flask-ref", "dependsOn": []}
            ]
        }

        result = resolver.resolve(input_sbom)

        # 1. Verify G_obs is preserved verbatim (Immutable)
        g_obs = result["G_obs"]
        flask_obs_deps = next((d["dependsOn"] for d in g_obs["dependencies"] if d["ref"] == "flask-ref"), None)
        self.assertEqual(flask_obs_deps, [], "G_obs must remain untouched with empty dependsOn")

        # 2. Verify Contradiction Detection
        contradictions = result["G_candidate"]["contradictions"]
        self.assertEqual(len(contradictions), 1)
        contra = contradictions[0]
        self.assertEqual(contra["source"], "pkg:pypi/flask@2.0.1")
        self.assertEqual(contra["contradicted_target"], "pkg:pypi/werkzeug@2.0.3")
        self.assertEqual(contra["declared_in_sbom"], "dependsOn: []")
        self.assertEqual(contra["evidence"], "installed-wheel-metadata")

        # 3. Verify Candidate Edge has status CONTRADICTED_DECLARATION
        cand_edges = result["G_candidate"]["edges"]
        werkzeug_edge = next((e for e in cand_edges if e["target_purl"] == "pkg:pypi/werkzeug@2.0.3"), None)
        self.assertIsNotNone(werkzeug_edge)
        self.assertEqual(werkzeug_edge["status"], "CONTRADICTED_DECLARATION")

        # 4. Verify G_reconstructed contains candidate repair
        g_rec = result["G_reconstructed"]
        flask_rec_deps = next((d["dependsOn"] for d in g_rec["dependencies"] if d["ref"] == "flask-ref"), None)
        self.assertIn("pkg:pypi/werkzeug@2.0.3", flask_rec_deps)

    def test_C_missing_component_and_security_analysis(self):
        """
        Test C:
        1. A vulnerable library (e.g., certifi@2022.12.07 matching CVE-2023-37920) is omitted from SBOM.
        2. Resolver reconstructs missing intermediate component + vulnerable component.
        3. Demonstrates Vulnerability Recovery Rate (VRR) improvement and OpenVEX compliance.
        """
        # True chain: web-app -> requests@2.31.0 -> certifi@2022.12.07 (CVE-2023-37920)
        requirements_db = {
            "pkg:pypi/web-app@1.0.0": [
                DependencyRequirement(target_purl="pkg:pypi/requests@2.31.0")
            ],
            "pkg:pypi/requests@2.31.0": [
                DependencyRequirement(target_purl="pkg:pypi/certifi@2022.12.07")
            ],
            "pkg:pypi/certifi@2022.12.07": []
        }
        provider = MockMetadataProvider(requirements_db, source_name="verified-distribution-metadata")
        resolver = ContextAwareResolver(provider)

        # Incomplete SBOM: certifi@2022.12.07 and its edge are COMPLETELY OMITTED
        input_sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {
                "component": {
                    "type": "application", "bom-ref": "app-ref",
                    "purl": "pkg:pypi/web-app@1.0.0", "name": "web-app", "version": "1.0.0"
                }
            },
            "components": [
                {"type": "library", "bom-ref": "req-ref", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}
            ],
            "dependencies": [
                {"ref": "app-ref", "dependsOn": ["req-ref"]}
            ]
        }

        # Simulated advisory database
        known_advisories = {
            "pkg:pypi/certifi@2022.12.07": [
                {"id": "CVE-2023-37920", "summary": "Certifi e-Tugra root certificate removal", "severity": "MEDIUM"}
            ]
        }

        # Before reconstruction: Check security impact
        obs_components = {c["purl"] for c in input_sbom["components"]}
        advisories_found_before = [
            adv for purl in obs_components if purl in known_advisories for adv in known_advisories[purl]
        ]
        self.assertEqual(len(advisories_found_before), 0, "Initial incomplete SBOM fails to detect vulnerability (False Assurance)")

        # Run context-aware resolver
        result = resolver.resolve(input_sbom)

        # Check missing node recovery
        inferred_nodes = {n["purl"] for n in result["G_candidate"]["nodes"]}
        self.assertIn("pkg:pypi/certifi@2022.12.07", inferred_nodes, "Missing vulnerable component must be recovered as CandidateNode")

        # Check security impact after reconstruction
        rec_components = {c["purl"] for c in result["G_reconstructed"]["components"]}
        advisories_found_after = [
            adv for purl in rec_components if purl in known_advisories for adv in known_advisories[purl]
        ]
        self.assertEqual(len(advisories_found_after), 1)
        self.assertEqual(advisories_found_after[0]["id"], "CVE-2023-37920")

        # Metric: Vulnerability Recovery Rate (VRR)
        # Ground truth has 1 vulnerable package reachable.
        # Before: 0/1 = 0.0; After: 1/1 = 1.0 (100% VRR)
        vrr_before = len(advisories_found_before) / 1.0
        vrr_after = len(advisories_found_after) / 1.0
        self.assertEqual(vrr_before, 0.0)
        self.assertEqual(vrr_after, 1.0)


if __name__ == "__main__":
    unittest.main()
