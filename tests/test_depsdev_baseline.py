import copy
import unittest

from depsdev_baseline import b6_from_response, dependencies_url


def response():
    return {"nodes": [{"versionKey": {"system": "PYPI", "name": name, "version": version}}
                       for name, version in [("App_Name", "1"), ("dep", "9"), ("leaf", "2")]],
            "edges": [{"fromNode": 0, "toNode": 1, "requirement": ">=2"},
                      {"fromNode": 1, "toNode": 2, "requirement": "==2"}]}


class TestDepsDevBaseline(unittest.TestCase):
    def test_remote_direct_edges_and_versions_are_preserved(self):
        raw = response()
        original = copy.deepcopy(raw)
        result = b6_from_response(raw, "pkg:pypi/app-name@1", {"sha256": "example"})
        self.assertEqual(result["predicted_edges"], [("pkg:pypi/app-name@1", "pkg:pypi/dep@9"),
                                                    ("pkg:pypi/dep@9", "pkg:pypi/leaf@2")])
        self.assertEqual(result["status"], "REMOTE_GRAPH_AVAILABLE")
        self.assertEqual(result["environment_alignment"]["status"], "Context-Uncertain")
        self.assertFalse(result["admissible_as_target_installation_truth"])
        self.assertEqual(raw, original)

    def test_invalid_indices_never_use_python_negative_indexing(self):
        raw = response()
        raw["edges"] = [{"fromNode": index, "toNode": 1} for index in (-1, 99, True, None)]
        result = b6_from_response(raw, "pkg:pypi/app-name@1", {})
        self.assertEqual(result["predicted_edges"], [])
        self.assertEqual(len(result["unresolved"]), 4)

    def test_mismatched_root_abstains(self):
        result = b6_from_response(response(), "pkg:pypi/app-name@2", {})
        self.assertEqual(result["status"], "ABSTAIN")
        self.assertEqual(result["predicted_nodes"], [])
        self.assertEqual(result["predicted_edges"], [])

    def test_remote_errors_and_unknown_ecosystem_are_retained(self):
        raw = response()
        raw["nodes"][1]["errors"] = ["unresolved requirement"]
        raw["nodes"][2]["versionKey"]["system"] = "NPM"
        raw["error"] = "partial resolution"
        result = b6_from_response(raw, "pkg:pypi/app-name@1", {})
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(len(result["unresolved"]), 4)
        self.assertEqual(len(result["predicted_edges"]), 1)

    def test_exact_root_required_and_urls_are_escaped(self):
        self.assertIn("app-name/versions/1%2Blocal:dependencies", dependencies_url("pkg:pypi/App_Name@1+local"))
        with self.assertRaises(ValueError):
            dependencies_url("pkg:pypi/app-name")


if __name__ == "__main__":
    unittest.main()
