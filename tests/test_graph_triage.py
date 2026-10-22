import copy
import unittest

from graph_triage import b5_assess, topology


def sbom(count=4, dependencies=None):
    result = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"bom-ref": str(i), "name": str(i)} for i in range(count)]}
    if dependencies is not None:
        result["dependencies"] = dependencies
    return result


class TestGraphTriage(unittest.TestCase):
    def test_missing_block_is_distinct_from_declared_empty_block(self):
        self.assertEqual(topology(sbom())["regime"], "no_edges")
        empty = topology(sbom(dependencies=[]))
        self.assertEqual(empty["regime"], "degenerate-with-edges")
        self.assertEqual(empty["orphan_ratio"], 1)

    def test_threshold_is_strict_and_connected_does_not_mean_one_component(self):
        document = sbom(dependencies=[{"ref": "0", "dependsOn": ["1"]}])
        result = topology(document)
        self.assertEqual(result["orphan_ratio"], 0.5)
        self.assertEqual(result["regime"], "connected")
        self.assertEqual(result["weak_components"], 3)
        document["components"].append({"bom-ref": "4"})
        self.assertEqual(topology(document)["regime"], "degenerate-with-edges")

    def test_empty_graph_has_undefined_ratios(self):
        result = topology(sbom(0))
        self.assertEqual(result["regime"], "EMPTY_GRAPH")
        self.assertIsNone(result["orphan_ratio"])

    def test_directed_paths_cycles_and_root_are_separate(self):
        document = sbom(dependencies=[{"ref": "0", "dependsOn": ["1"]},
            {"ref": "1", "dependsOn": ["2"]}, {"ref": "2", "dependsOn": ["0"]}])
        result = b5_assess(document, ["0"])
        by_ref = {row["target_ref"]: row for row in result["assessments"]}
        self.assertEqual(by_ref["0"]["evidence_level"], 0)
        self.assertEqual(by_ref["2"]["path_refs"], ["0", "1", "2"])
        self.assertEqual(by_ref["3"]["status"], "UNKNOWN")
        self.assertEqual(b5_assess(sbom(2, [{"ref": "1", "dependsOn": ["0"]}]), ["0"])
                         ["assessments"][1]["status"], "UNKNOWN")

    def test_connected_graph_and_complete_claim_do_not_authorize_negative_verdict(self):
        document = sbom(dependencies=[{"ref": "0", "dependsOn": ["1"]}])
        document["compositions"] = [{"aggregate": "complete", "dependencies": ["0"]}]
        original = copy.deepcopy(document)
        result = b5_assess(document, ["0"], ["3", "absent"])
        self.assertTrue(all(row["status"] == "UNKNOWN" and row["openvex_status"] == "under_investigation"
                            for row in result["assessments"]))
        self.assertEqual(result["topology"]["composition_claims"][0]["dependencies"], ["0"])
        self.assertEqual(document, original)

    def test_unknown_roots_are_not_invented_from_zero_indegree(self):
        result = b5_assess(sbom(dependencies=[{"ref": "0", "dependsOn": ["1"]}]))
        self.assertEqual(result["root_refs"], [])
        self.assertEqual(result["counts"], {"UNKNOWN": 4})

    def test_nested_root_services_and_non_purl_inventory_are_retained(self):
        document = sbom(0, [{"ref": "root", "dependsOn": ["service"]}])
        document["metadata"] = {"component": {"bom-ref": "root", "components": [{"bom-ref": "nested"}]}}
        document["services"] = [{"bom-ref": "service"}]
        result = b5_assess(document)
        self.assertEqual(result["topology"]["nodes"], 3)
        self.assertEqual(result["counts"]["DEPENDENCY_PATH_OBSERVED"], 1)

    def test_duplicate_and_dangling_refs_cannot_manufacture_paths(self):
        document = sbom(2, [{"ref": "0", "dependsOn": ["1", "dangling"]}])
        document["components"].append({"bom-ref": "1"})
        document["components"].append({"name": "no reference"})
        result = b5_assess(document, ["0"], ["1", "dangling"])
        self.assertEqual(result["topology"]["edges"], 0)
        self.assertEqual(result["topology"]["graph_index_status"], "PARTIAL")
        self.assertEqual(result["counts"], {"UNKNOWN": 2})

    def test_duplicate_edges_and_explicit_leaves(self):
        result = topology(sbom(2, [{"ref": "0", "dependsOn": ["1", "1"]},
                                   {"ref": "1", "dependsOn": []}]))
        self.assertEqual(result["edges"], 1)
        self.assertEqual(result["explicit_empty_source_count"], 1)

    def test_unsupported_format_and_malformed_block_fail(self):
        with self.assertRaises(ValueError):
            topology({"spdxVersion": "SPDX-2.3"})
        with self.assertRaises(ValueError):
            topology({**sbom(), "dependencies": None})


if __name__ == "__main__":
    unittest.main()
