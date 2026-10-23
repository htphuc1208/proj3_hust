"""Raw-generator normalization must preserve evidence rather than manufacture omissions."""
import unittest
from pathlib import Path
from research_core import graph, load, normalize_sbom, validate_cdx
from scripts.run_scientific_validation import PILOTS

ROOT = Path(__file__).resolve().parents[1]


class TestRealGeneratorReconstruction(unittest.TestCase):
    def test_raw_relationships_survive_normalization(self):
        for name, base, _ in PILOTS:
            raw = load(ROOT / base / "generator_syft.cdx.json")
            norm, audit = normalize_sbom(raw, name, bootstrap=("pip", "setuptools"))
            refs = {row["original_ref"]: row["canonical_identity"] for row in audit["components"] if row["retained_for_inference"]}
            expected = {(refs[d["ref"]], refs[t]) for d in raw.get("dependencies", []) for t in d.get("dependsOn", [])
                        if d.get("ref") in refs and t in refs}
            self.assertEqual(graph(norm)[1], expected)
            self.assertTrue(validate_cdx(norm)["valid"])
            self.assertEqual(len(audit["components"]), len(raw["components"]) + bool(raw.get("metadata", {}).get("component")))
