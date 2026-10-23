"""Synthetic input-generation contracts, not empirical recovery results."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from controlled_reference import reference_spdx
from sbom_recovery.formats import NativeDocument, validate_native
from sbom_recovery.metrics import controlled_mask, graph_facts, metadata_facts


class ControlledReferenceTests(unittest.TestCase):
    def setUp(self):
        self.reference = {"project": "alpha", "nodes": [
            {"name": "alpha", "version": "1", "purl": "pkg:pypi/alpha@1"},
            {"name": "beta", "version": "2", "purl": "pkg:pypi/beta@2"}],
            "edges": [{"from": "alpha", "to": "beta"}]}
        self.labels = {"alpha": {"name": "alpha", "version": "1", "purl": "pkg:pypi/alpha@1", "licenseDeclared": "MIT"},
                       "beta": {"name": "beta", "version": "2", "purl": "pkg:pypi/beta@2"}}

    def make(self):
        return reference_spdx(self.reference, self.labels, ["pkg:pypi/alpha@1"], "2026-10-29T00:00:00Z")

    def test_native_observation_matches_independent_inventory_and_direct_edges(self):
        before = deepcopy(self.reference)
        document = self.make()
        self.assertTrue(validate_native(document)["valid"])
        self.assertEqual(graph_facts(document), ({"pkg:pypi/alpha@1", "pkg:pypi/beta@2"},
                                                {("pkg:pypi/alpha@1", "pkg:pypi/beta@2")}))
        self.assertEqual(len(metadata_facts(document)), 7)
        self.assertEqual(self.reference, before)
        self.assertFalse(any(r["spdxElementId"] == "SPDXRef-DOCUMENT" for r in document["relationships"] if r["relationshipType"] == "DEPENDS_ON"))

    def test_masked_graph_is_a_subgraph_and_keeps_the_predeclared_root(self):
        document = self.make()
        for family in ("component", "metadata", "dependency"):
            masked, log = controlled_mask(document, 1., 11, family)
            self.assertEqual(log["mechanism"], "CONTROLLED_MCAR")
            self.assertLessEqual(graph_facts(masked)[0], graph_facts(document)[0])
            self.assertLessEqual(graph_facts(masked)[1], graph_facts(document)[1])
            if family == "component":
                self.assertEqual(graph_facts(masked)[0], {"pkg:pypi/alpha@1"})
            elif family == "dependency":
                self.assertFalse(NativeDocument(masked).edges())
                self.assertEqual(graph_facts(masked)[0], graph_facts(document)[0])

    def test_label_disagreement_and_missing_endpoints_fail_closed(self):
        self.labels["beta"]["version"] = "99"
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.make()
        self.labels["beta"]["version"] = "2"
        self.reference["edges"][0]["to"] = "absent"
        with self.assertRaisesRegex(ValueError, "dangling"):
            self.make()

    def test_campaign_masks_independent_labels_without_adding_them_to_evidence(self):
        from benchmark import as_cyclonedx
        from research_core import load
        from sbom_recovery.campaign import run_case, prepare_store
        from sbom_recovery.contracts import TargetContext
        from sbom_recovery.evidence import EvidenceStore
        from sbom_recovery.formats import sha
        from sbom_recovery.storage import save
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/"capture";out=Path(temp)/"case"
            (root/"runtime/target").mkdir(parents=True)
            ctx=TargetContext(os_name="posix",sys_platform="linux",platform_machine="x86_64",python_version="3.11",
                python_full_version="3.11.16",platform_system="Linux",active_extras=[],target_id=sha([]),
                evidence_cutoff="2026-10-28T16:59:59Z",root_purls=["pkg:pypi/alpha@1"])
            save(root/"context.json",ctx.model_dump())
            save(root/"capture.json",{"status":"COMPLETE","project":{"name":"alpha","version":"1","partition":"development"},
                "completed_at":"2026-10-29T00:00:00Z","historical_resolution_horizon":ctx.evidence_cutoff})
            reference={**self.reference,"roots":["alpha"]}
            save(root/"oracle/installed_reference.json",reference)
            save(root/"oracle/installed_reference.cdx.json",as_cyclonedx(reference))
            save(root/"oracle/installed_field_labels.json",{"fields":self.labels})
            # A deliberately different scanner inventory proves the case input
            # comes from the independent reference, not the scanner output.
            scanner_ref={"project":"wrong","nodes":[{"name":"wrong","version":"99","purl":"pkg:pypi/wrong@99"}],"edges":[]}
            scanner=reference_spdx(scanner_ref,{},["pkg:pypi/wrong@99"],"2026-10-29T00:00:00Z")
            save(root/"runtime/syft.spdx.json",scanner)
            result=run_case(root,out,methods=["observed"],family="component",rate=1.,mask_origin="reference")
            self.assertEqual(result["records"][0]["input_origin"],"INDEPENDENT_REFERENCE_MASK")
            observed=load(out/"input.spdx.json")
            self.assertEqual(graph_facts(observed)[0],{"pkg:pypi/alpha@1"})
            seal=load(out/"observed/seal.json")
            self.assertTrue(seal["oracle_read_before_seal"])
            self.assertFalse(seal["oracle_exposed_to_prediction_worker"])
            store=EvidenceStore(Path(temp)/"evidence")
            try:
                prepare_store(root,observed,store,ctx,"fixed")
                raw=[store.read(r.evidence_id)[1] for r in store.records()]
                self.assertFalse(any(b"pkg:pypi/beta@2" in data for data in raw))
                self.assertTrue(any(b"pkg:pypi/wrong@99" in data for data in raw))
            finally:
                store.close()
            original=(out/"input.spdx.json").read_bytes()
            with self.assertRaisesRegex(ValueError,"CASE_INPUT_CHANGED"):
                run_case(root,out,methods=["observed"],family="component",rate=1.,mask_origin="scanner")
            self.assertEqual((out/"input.spdx.json").read_bytes(),original)


if __name__ == "__main__":
    unittest.main()
