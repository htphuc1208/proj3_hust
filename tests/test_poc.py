import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from poc import EvidenceProvider, AdvisoryProvider, reconstruct, shortest_path, simple_static_callgraph


class TestPoC(unittest.TestCase):
    def setUp(self):
        self.sbom = json.loads((ROOT / "fixtures/sbom_incomplete.json").read_text())
        self.provider = EvidenceProvider(ROOT / "fixtures/registry.json")

    def test_exact_synthetic_completion(self):
        result, purls, graph, nodes, edges, blocked = reconstruct(self.sbom, self.provider)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(len(edges), 2)
        self.assertEqual(len(purls), 4)
        root = result["metadata"]["component"]["bom-ref"]
        self.assertEqual(len(shortest_path(graph, root, purls["pkg:pypi/acme-unsafe@0.9.0"])), 4)
        self.assertEqual(blocked, [])

    def test_explicit_empty_dependency_declaration_is_respected(self):
        self.sbom["dependencies"].append({"ref":"router-ref","dependsOn":[]})
        _, _, _, nodes, edges, _ = reconstruct(self.sbom, self.provider)
        self.assertFalse(nodes)
        self.assertEqual([(e["from"],e["to"]) for e in edges],
                         [("pkg:pypi/acme-web@1.0.0","pkg:pypi/acme-router@1.2.0")])

    def test_no_source_cannot_prove_reachability(self):
        fixture = AdvisoryProvider(ROOT / "fixtures/advisories.json")
        reports = fixture.query("pkg:pypi/acme-unsafe@0.9.0")
        self.assertEqual(reports[0]["id"], "SIMULATED-2026-0001")
        self.assertIsNone(shortest_path({}, "app.main", reports[0]["function"]))

    def test_static_call_path_present(self):
        graph = simple_static_callgraph(ROOT / "demo_source")
        path = shortest_path(graph, "app.main", "acme_unsafe.parser.parse_untrusted")
        self.assertEqual(path, ["app.main", "acme_web.service.handle_request",
                                "acme_router.routing.dispatch", "acme_unsafe.parser.parse_untrusted"])


if __name__ == "__main__":
    unittest.main()
