"""Security and independent scoring invariants for evidence-seeking V3."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sbom_recovery.investigation.evaluation import paired_bootstrap, score, score_files, validate_splits
from sbom_recovery.investigation.security import assess, affected_version


TARGET = {"target_id": "release", "revision_ref": "abc123", "context_id": "linux", "view": "RESOLVED"}


def component(ref, name="lib", version="1.2.0", locator=None, status="SUPPORTED"):
    return {"id": ref, "ecosystem": "npm", "name": name, "version": version,
            "purl": f"pkg:npm/{name}@{version}", "locator": locator, "status": status, "evidence_ids": ["E1"]}


def advisory(ident="CVE-2026-001", aliases=None, events=None, range_type="SEMVER"):
    return {"id": ident, "aliases": aliases or [], "affected": [{"package": {"ecosystem": "npm", "name": "lib"},
            "ranges": [{"type": range_type, "events": events or [{"introduced": "1.0.0"}, {"fixed": "1.3.0"}]}]}]}


def snapshot(rows=None):
    return {"schema_version": "osv-snapshot-v1", "advisories": rows if rows is not None else [advisory()]}


def prediction():
    return {"target": dict(TARGET), "components": [component("p-root", "app", "1.0.0", ""),
            component("p-lib", locator="node_modules/lib")], "edges": [
            {"source": "p-root", "target": "p-lib", "relationship_type": "direct_dependency", "status": "SUPPORTED"}],
            "roots": ["p-root"]}


def oracle():
    value = prediction()
    for row in value["components"]:
        row["id"] = row["id"].replace("p-", "gold-")
    for row in value["edges"]:
        row["source"], row["target"] = row["source"].replace("p-", "gold-"), row["target"].replace("p-", "gold-")
    value["roots"] = ["gold-root"]
    value.update(schema_version="reconciliation-oracle-v1", coverage={"components": "COMPLETE", "edges": "COMPLETE", "paths": "COMPLETE"})
    return value


class SecurityMatchingTests(unittest.TestCase):
    def test_fixed_introduced_and_multiple_ranges(self):
        entry = advisory()["affected"][0]
        self.assertFalse(affected_version("0.9.0", entry, "npm"))
        self.assertTrue(affected_version("1.0.0", entry, "npm"))
        self.assertTrue(affected_version("1.2.9", entry, "npm"))
        self.assertFalse(affected_version("1.3.0", entry, "npm"))
        entry["ranges"][0]["events"] += [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]
        self.assertTrue(affected_version("2.0.0", entry, "npm"))
        self.assertFalse(affected_version("2.1.0", entry, "npm"))

    def test_last_affected_inclusive_and_limit_exclusive(self):
        entry = advisory(events=[{"introduced": "0"}, {"last_affected": "1.2.0"}])["affected"][0]
        self.assertTrue(affected_version("1.2.0", entry, "cargo"))
        self.assertFalse(affected_version("1.2.1", entry, "cargo"))
        entry["ranges"][0]["events"] = [{"introduced": "0"}, {"limit": "1.2.0"}]
        self.assertFalse(affected_version("1.2.0", entry, "npm"))
        self.assertTrue(affected_version("1.1.0", entry, "npm"))

    def test_semver_prerelease_and_build_metadata(self):
        entry = advisory(events=[{"introduced": "1.0.0-alpha.2"}, {"fixed": "1.0.0"}])["affected"][0]
        self.assertFalse(affected_version("1.0.0-alpha.1", entry, "npm"))
        self.assertTrue(affected_version("1.0.0-alpha.10", entry, "npm"))
        self.assertTrue(affected_version("1.0.0-beta+build.2", entry, "npm"))
        self.assertFalse(affected_version("1.0.0+build.2", entry, "npm"))
        self.assertIsNone(affected_version("1.0.0-alpha.01", entry, "npm"))

    def test_exact_versions_and_unsupported_ranges(self):
        entry = {"versions": ["v1"], "ranges": [{"type": "GIT", "events": [{"introduced": "hash"}]}]}
        self.assertTrue(affected_version("v1", entry, "npm"))
        self.assertIsNone(affected_version("v2", entry, "npm"))
        self.assertIsNone(affected_version(None, entry, "npm"))
        entry = advisory(range_type="ECOSYSTEM")["affected"][0]
        self.assertIsNone(affected_version("1.2.0", entry, "maven"))
        self.assertTrue(affected_version("1.2.0", entry, "cargo"))

    def test_fixed_semver_does_not_override_an_unsupported_git_range(self):
        entry = advisory()["affected"][0]
        entry["ranges"].append({"type": "GIT", "events": [{"introduced": "hash"}]})
        self.assertIsNone(affected_version("2.0.0", entry, "npm"))
        self.assertTrue(affected_version("1.2.0", entry, "npm"))

    def test_conflicting_identity_cannot_produce_a_confirmed_match(self):
        value = prediction()
        value["components"][1]["status"] = "CONFLICT"
        self.assertEqual(assess(value, snapshot())["findings"][0]["status"], "POTENTIALLY_AFFECTED")

    def test_invalid_events_abstain(self):
        for events in ([{"fixed": "1.3.0"}], [{"introduced": "0", "fixed": "1.3.0"}],
                       [{"introduced": "0"}, {"fixed": "1.3.0"}, {"last_affected": "1.2.0"}]):
            entry = advisory(events=events)["affected"][0]
            self.assertIsNone(affected_version("1.2.0", entry, "npm"))

    def test_aliases_deduplicate_transitively_and_not_related(self):
        a = advisory("GHSA-a", ["CVE-a"])
        b = advisory("OSV-a", ["GHSA-a"])
        c = advisory("GHSA-b")
        c["related"] = ["CVE-a"]
        findings = assess(prediction(), snapshot([a, b, c]))["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["advisory_id"], "CVE-a")
        self.assertEqual(findings[0]["aliases"], ["CVE-a", "GHSA-a", "OSV-a"])

    def test_confirmed_vulnerability_and_graph_exposure_are_separate(self):
        value = prediction()
        row = assess(value, snapshot())["findings"][0]
        self.assertEqual(row["status"], "CONFIRMED_AFFECTED")
        self.assertEqual(row["dependency_exposure"], "OBSERVED_PATH")
        value["edges"] = []
        row = assess(value, snapshot())["findings"][0]
        self.assertEqual(row["status"], "CONFIRMED_AFFECTED")
        self.assertEqual(row["dependency_exposure"], "UNKNOWN")
        self.assertEqual(row["exploitability"], "NOT_ASSESSED")

    def test_contains_and_unknown_edges_do_not_establish_dependency_paths(self):
        value = prediction()
        value["edges"][0]["relationship_type"] = "contains"
        self.assertEqual(assess(value, snapshot())["findings"][0]["dependency_exposure"], "UNKNOWN")
        value["edges"][0].update(relationship_type="direct_dependency", status="UNKNOWN")
        self.assertEqual(assess(value, snapshot())["findings"][0]["dependency_exposure"], "UNKNOWN")

    def test_uncertain_components_never_confirmed_or_dismissed(self):
        value = prediction()
        value["components"][1]["status"] = "UNKNOWN"
        self.assertEqual(assess(value, snapshot())["findings"][0]["status"], "POTENTIALLY_AFFECTED")
        value["components"][1].update(version="2.0.0", purl="pkg:npm/lib@2.0.0")
        self.assertEqual(assess(value, snapshot())["findings"][0]["status"], "UNKNOWN")

    def test_registry_nonmatch_and_bad_identity_are_unknown(self):
        value = prediction()
        value["components"][1]["purl"] = "pkg:npm/other@1.2.0"
        report = assess(value, snapshot())
        self.assertEqual(report["findings"], [])
        self.assertEqual({r["reason"] for r in report["unknowns"]}, {"NO_MATCH_IN_SNAPSHOT", "UNRESOLVED_PACKAGE_IDENTITY"})

    def test_scoped_npm_names_accept_split_or_full_namespace_forms(self):
        value = prediction()
        row = value["components"][1]
        row.update(namespace="@scope", name="@scope/lib", purl="pkg:npm/%40scope/lib@1.2.0")
        record = advisory()
        record["affected"][0]["package"]["name"] = "@scope/lib"
        self.assertEqual(assess(value, snapshot([record]))["findings"][0]["status"], "CONFIRMED_AFFECTED")
        row["name"] = "lib"
        self.assertEqual(assess(value, snapshot([record]))["findings"][0]["status"], "CONFIRMED_AFFECTED")

    def test_withdrawn_advisories_are_not_active_and_digest_is_stable(self):
        row = advisory()
        row["withdrawn"] = "2026-11-01T00:00:00Z"
        report = assess(prediction(), snapshot([row]))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["snapshot_sha256"], assess(prediction(), deepcopy(snapshot([row])))["snapshot_sha256"])


class OracleEvaluationTests(unittest.TestCase):
    def test_independent_ids_score_identity_edges_and_paths(self):
        result = score(prediction(), oracle())
        for domain in ("components", "edges", "paths"):
            self.assertEqual(result[domain]["f1"], 1.0)
        self.assertEqual(result["fields"]["version"]["accuracy"], 1.0)

    def test_paths_score_all_roots_instead_of_one_arbitrary_witness(self):
        value, gold = prediction(), oracle()
        value["components"].append(component("p-other", "other-app", "1.0.0", "other-root"))
        gold["components"].append(component("gold-other", "other-app", "1.0.0", "other-root"))
        value["roots"].append("p-other")
        gold["roots"].insert(0, "gold-other")
        value["edges"].append({"source": "p-other", "target": "p-lib", "relationship_type": "direct_dependency", "status": "SUPPORTED"})
        gold["edges"].append({"source": "gold-other", "target": "gold-lib", "relationship_type": "direct_dependency", "status": "SUPPORTED"})
        report = score(value, gold)
        self.assertEqual(report["paths"]["f1"], 1.0)
        self.assertEqual(report["paths"]["true_positive"], 2)

    def test_scope_mismatch_and_missing_scope_rejected(self):
        for key in ("revision_ref", "context_id", "view", "target_id"):
            bad = oracle()
            bad["target"][key] = "other"
            with self.assertRaises(ValueError):
                score(prediction(), bad)
        bad = oracle()
        del bad["target"]["revision_ref"]
        with self.assertRaises(ValueError):
            score(prediction(), bad)
        value = prediction()
        value["target"]["context"] = {"context_id": value["target"].pop("context_id")}
        self.assertEqual(score(value, oracle())["components"]["f1"], 1.0)

    def test_missing_labels_do_not_become_false_positives(self):
        value, gold = prediction(), oracle()
        value["components"].append(component("extra", "extra", "1.0.0", "node_modules/extra"))
        gold["coverage"] = {}
        result = score(value, gold)
        self.assertEqual(result["components"]["false_positive"], 0)
        self.assertEqual(result["components"]["unscored_predictions"], 1)
        gold["coverage"]["components"] = "COMPLETE"
        self.assertEqual(score(value, gold)["components"]["false_positive"], 1)

    def test_explicit_absent_labels_count_without_complete_inventory(self):
        value, gold = prediction(), oracle()
        gold["components"][1]["status"] = "ABSENT"
        gold["coverage"] = {}
        self.assertEqual(score(value, gold)["components"]["false_positive"], 1)

    def test_unknown_oracle_labels_excluded(self):
        gold = oracle()
        gold["components"][1]["status"] = "UNKNOWN"
        result = score(prediction(), gold)
        self.assertEqual(result["components"]["labeled_positive"], 1)
        self.assertEqual(result["components"]["false_positive"], 0)
        self.assertEqual(result["components"]["unscored_predictions"], 1)
        self.assertEqual(result["coverage"]["oracle_unknown_components"], 1)

    def test_candidate_graphs_scored_separately_from_supported_graphs(self):
        value = prediction()
        for row in value["components"] + value["edges"]:
            row["status"] = "UNKNOWN"
        result = score(value, oracle())
        self.assertEqual(result["edges"]["f1"], 0.0)
        self.assertEqual(result["paths"]["f1"], 0.0)
        self.assertEqual(result["candidate_edges"]["f1"], 1.0)
        self.assertEqual(result["candidate_paths"]["f1"], 1.0)

    def test_unknown_edge_and_path_labels_override_complete_coverage(self):
        gold = oracle()
        gold["edges"][0]["status"] = "UNKNOWN"
        gold["paths"] = [{"source": "gold-root", "target": "gold-lib", "present": None}]
        result = score(prediction(), gold)
        self.assertEqual(result["edges"]["false_positive"], 0)
        self.assertEqual(result["edges"]["unscored_predictions"], 1)
        self.assertEqual(result["paths"]["false_positive"], 0)

    def test_edge_scope_measured_separately_and_unknown_scope_abstains(self):
        value, gold = prediction(), oracle()
        gold["edges"][0]["scope"] = "runtime"
        value["edges"][0]["scope"] = "unknown"
        result = score(value, gold)
        self.assertEqual(result["edges"]["f1"], 1.0)
        self.assertEqual(result["edge_scope"]["accuracy"], 0.0)
        self.assertEqual(result["edge_scope"]["abstained"], 1)
        value["edges"][0]["scope"] = "test"
        self.assertEqual(score(value, gold)["edge_scope"]["incorrect"], 1)
        value["edges"].append({**value["edges"][0], "scope": "runtime", "status": "UNKNOWN"})
        result = score(value, gold)
        self.assertEqual(result["candidate_edges"]["true_positive"], 1)
        self.assertEqual(result["candidate_edge_scope"]["accuracy"], 1.0)

    def test_repeated_identity_occurrences_are_not_collapsed(self):
        value, gold = prediction(), oracle()
        value["components"].append(component("p-copy", locator="nested/node_modules/lib"))
        result = score(value, gold)
        self.assertEqual(result["components"]["true_positive"], 2)
        self.assertEqual(result["components"]["false_positive"], 1)
        gold["components"].append(component("gold-copy", locator="nested/node_modules/lib"))
        self.assertEqual(score(value, gold)["components"]["f1"], 1.0)

    def test_unlocated_duplicate_endpoints_abstain_for_edges(self):
        value, gold = prediction(), oracle()
        value["components"][1]["locator"] = None
        gold["components"][1]["locator"] = None
        value["components"].append(component("p-copy"))
        gold["components"].append(component("gold-copy"))
        result = score(value, gold)
        self.assertEqual(result["components"]["f1"], 1.0)
        self.assertEqual(result["coverage"]["unscorable_predicted_edges"], 1)

    def test_wrong_version_reduces_component_and_field_accuracy(self):
        value = prediction()
        value["components"][1].update(version="1.1.0", purl="pkg:npm/lib@1.1.0")
        result = score(value, oracle())
        self.assertEqual(result["components"]["false_positive"], 1)
        self.assertEqual(result["components"]["false_negative"], 1)
        self.assertEqual(result["fields"]["version"]["accuracy"], .5)

    def test_unknown_prediction_reported_as_abstention(self):
        value = prediction()
        value["components"][1]["status"] = "UNKNOWN"
        result = score(value, oracle())
        self.assertEqual(result["components"]["false_negative"], 1)
        self.assertEqual(result["candidate_components"]["f1"], 1.0)
        self.assertEqual(result["coverage"]["unknown_fraction"], .5)

    def test_security_matching_and_false_safe_are_scored(self):
        value, gold = prediction(), oracle()
        value["security"] = assess(value, snapshot())
        gold["security"] = {"snapshot_sha256": value["security"]["snapshot_sha256"], "labels": [
            {"component_id": "gold-lib", "advisory_id": "CVE-2026-001", "affected": True}]}
        self.assertEqual(score(value, gold)["security"]["f1"], 1.0)
        value["security"]["findings"][0]["status"] = "SAFE"
        self.assertEqual(score(value, gold)["security"]["false_safe_rate"], 1.0)
        value["security"]["snapshot_sha256"] = "other"
        with self.assertRaises(ValueError):
            score(value, gold)

    def test_candidate_security_preserves_uncertain_matching_coverage(self):
        value, gold = prediction(), oracle()
        value["components"][1]["status"] = "UNKNOWN"
        value["security"] = assess(value, snapshot())
        gold["security"] = {"labels": [{"component_id": "gold-lib", "advisory_id": "CVE-2026-001", "affected": True}]}
        report = score(value, gold)
        self.assertEqual(report["security"]["recall"], 0.0)
        self.assertEqual(report["candidate_security"]["recall"], 1.0)

    def test_wrong_corrected_version_can_be_an_incorrect_dismissal(self):
        value, gold = prediction(), oracle()
        value["components"][1].update(version="2.0.0", purl="pkg:npm/lib@2.0.0")
        value["security"] = assess(value, snapshot())
        gold["security"] = {"labels": [{"component_id": "gold-lib", "advisory_id": "CVE-2026-001", "affected": True}]}
        report = score(value, gold)
        self.assertEqual(report["security"]["incorrect_dismissal_rate"], 1.0)

    def test_sealed_prediction_mutation_is_rejected_before_labels_are_opened(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "prediction.json"
            path.write_text(json.dumps(prediction()))
            frozen = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / "seal.json").write_text(json.dumps({"schema_version": "investigation-seal-v1", "files": {"prediction.json": frozen}}))
            path.write_text(json.dumps({}))
            # The nonexistent oracle must not be accessed after an invalid seal.
            with self.assertRaisesRegex(ValueError, "changed"):
                score_files(path, root / "missing-oracle.json")

    def test_seal_verification_and_output_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "prediction.json"
            path.write_text(json.dumps(prediction()))
            (root / "oracle.json").write_text(json.dumps(oracle()))
            frozen = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / "seal.json").write_text(json.dumps({"schema_version": "investigation-seal-v1", "files": {"prediction.json": frozen}}))
            self.assertTrue(score_files(path, root / "oracle.json")["seal_verified"])
            with self.assertRaises(ValueError):
                score_files(path, root / "oracle.json", path)

    def test_score_files_and_project_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "prediction.json").write_text(json.dumps(prediction()))
            (root / "oracle.json").write_text(json.dumps(oracle()))
            report = score_files(root / "prediction.json", root / "oracle.json", root / "score.json")
            self.assertEqual(json.loads((root / "score.json").read_text()), report)
        rows = [{"project_id": project, "method": method, "metrics": {"f1": value}}
                for project in ("a", "b") for method, value in (("P2", .5), ("P4", .75))]
        report = paired_bootstrap(rows, "f1", samples=100)
        self.assertEqual(report["projects"], 2)
        self.assertEqual(report["delta"], .25)
        self.assertEqual(report["ci95"], [.25, .25])

    def test_lineage_split_leakage_rejected(self):
        rows = [{"project_id": "a", "lineage_id": "family", "split": "dev"},
                {"project_id": "b", "lineage_id": "family", "split": "test"}]
        with self.assertRaises(ValueError):
            validate_splits(rows)
        rows[1]["split"] = "dev"
        self.assertTrue(validate_splits(rows)["valid"])


if __name__ == "__main__":
    unittest.main()
