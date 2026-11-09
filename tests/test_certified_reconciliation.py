"""Semantic counterexamples and certificate falsification, not accuracy evidence."""
from copy import deepcopy
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from packaging.requirements import Requirement

from sbom_recovery.core.formats import NativeDocument, sha
from sbom_recovery.campaign.targets import metadata_inventory
from sbom_recovery.reconciliation.contracts_v2 import ContextKnowledgeV2, occurrence_id
from sbom_recovery.reconciliation.certified_evidence import collect_evidence, read_bundle, EvidenceView
from sbom_recovery.reconciliation.certified_reconciliation import reconcile_certified, propose, run
from sbom_recovery.reconciliation.certificate_checker import check_decision, check_decisions
from sbom_recovery.reconciliation.certified_semantics import marker_bounds
from sbom_recovery.reconciliation.certified_baselines import metadata_control
from sbom_recovery.reconciliation.contracts_v2 import EvidenceManifestV2, EvidenceSourceV2

ROOT = Path(__file__).resolve().parents[1]
INSTALLATION = "lib/python3.11/site-packages"


class CertifiedReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                         "components": [], "dependencies": []}
        self.put("alpha", "1", "Requires-Dist: beta>=2\n")
        self.put("beta", "2", "")
        self.put("unrelated", "1", "")

    def put(self, name, version, requirements, *, ref=None, directory=None):
        relative = f"{INSTALLATION}/{directory or f'{name}-{version}.dist-info'}/METADATA"
        path = self.target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Metadata-Version: 2.3\nName: {name}\nVersion: {version}\n{requirements}\n")
        ref = ref or name
        self.document["components"] = [c for c in self.document["components"] if c["bom-ref"] != ref]
        self.document["components"].append({"type": "library", "bom-ref": ref, "name": name,
            "version": version, "purl": f"pkg:pypi/{name}@{version}",
            "properties": [{"name": "sbom-recovery:metadata-path", "value": relative}]})

    def bundle(self, *, complete=True, unknown_platform=False, omit=()):
        target_id = metadata_inventory(self.target)[1]
        self.context = ContextKnowledgeV2(target_id=target_id, installation_scope=INSTALLATION,
            evidence_cutoff="2026-11-09T00:00:00Z", root_requests_complete=complete,
            marker_values={"python_version": "3.11", "python_full_version": "3.11.16",
                           "sys_platform": None if unknown_platform else "linux"})
        output = self.root / f"evidence-{len(list(self.root.glob('evidence-*')))}"
        collect_evidence(self.document, self.context, self.target, "2026-11-08T00:00:00Z", output)
        manifest, raw = read_bundle(output / "manifest.json")
        for source in manifest.sources:
            if any(f"/{name}-" in source.occurrence_path for name in omit):
                source.acquired = False
                raw.pop(source.source_id)
        return manifest, raw

    def execute(self, **kwargs):
        manifest, raw = self.bundle(**kwargs)
        return reconcile_certified(self.document, self.context, manifest, raw)

    def observed(self, source="alpha", target="beta"):
        self.document["dependencies"].append({"ref": source, "dependsOn": [target]})

    def test_adds_supported_edge_despite_explicit_empty_observation(self):
        self.document["dependencies"] = [{"ref": "alpha", "dependsOn": []}]
        before = deepcopy(self.document)
        result = self.execute()
        self.assertIn(("alpha", "beta"), NativeDocument(result["document"]).edges())
        self.assertEqual(self.document, before)
        self.assertTrue(result["validation"]["valid"])
        self.assertEqual(result["verification"]["authorized_changes"], 1)

    def test_partial_evidence_closes_only_parent_declarations(self):
        self.put("alpha", "1", "")
        self.observed()
        result = self.execute(omit=["unrelated"], complete=False, unknown_platform=True)
        self.assertNotIn(("alpha", "beta"), NativeDocument(result["document"]).edges())
        self.assertEqual(result["decisions"][0]["reason"], "NO_MATCHING_DECLARATION")

    def test_unread_identity_cannot_prove_unique_positive_endpoint(self):
        result = self.execute(omit=["unrelated"])
        self.assertFalse(NativeDocument(result["document"]).edges())
        self.assertEqual(result["counts"], {"UNKNOWN": 1})

    def test_known_false_conjunct_survives_other_unknown_marker(self):
        self.put("alpha", "1", 'Requires-Dist: beta; sys_platform == "win32" and platform_release == "x"\n')
        self.observed()
        result = self.execute(omit=["unrelated"], complete=False)
        self.assertFalse(NativeDocument(result["document"]).edges())

    def test_unknown_extra_is_different_from_known_empty(self):
        self.put("alpha", "1", 'Requires-Dist: beta; extra == "optional"\n')
        self.observed()
        uncertain = self.execute(complete=False)
        closed = self.execute(complete=True)
        self.assertIn(("alpha", "beta"), NativeDocument(uncertain["document"]).edges())
        self.assertFalse(NativeDocument(closed["document"]).edges())
        self.assertIsNotNone(closed["decisions"][0]["certificate"]["activation_upper"])

    def test_transitive_activation_and_unseeded_cycle(self):
        self.put("alpha", "1", 'Requires-Dist: beta[optional]>=2\n')
        self.put("beta", "2", 'Requires-Dist: unrelated; extra == "optional"\n')
        result = self.execute()
        self.assertEqual(NativeDocument(result["document"]).edges(), {("alpha", "beta"), ("beta", "unrelated")})
        decisions = {d["source_ref"]: d for d in result["decisions"]}
        self.assertTrue(decisions["beta"]["certificate"]["activation_steps"])
        self.put("alpha", "1", 'Requires-Dist: beta[optional]; extra == "optional"\n')
        self.put("beta", "2", 'Requires-Dist: alpha[optional]; extra == "optional"\n')
        self.document["dependencies"] = [{"ref": "alpha", "dependsOn": ["beta"]}]
        self.assertFalse(NativeDocument(self.execute()["document"]).edges())

    def test_unknown_activating_marker_prevents_negative(self):
        self.put("alpha", "1", 'Requires-Dist: beta[optional]; platform_release == "x"\n')
        self.put("beta", "2", 'Requires-Dist: unrelated; extra == "optional"\n')
        self.observed("beta", "unrelated")
        result = self.execute()
        self.assertIn(("beta", "unrelated"), NativeDocument(result["document"]).edges())

    def test_same_purl_multiple_physical_occurrences_do_not_merge(self):
        self.put("beta", "2", "", ref="beta-copy", directory="beta_copy-2.dist-info")
        result = self.execute()
        self.assertFalse(NativeDocument(result["document"]).edges())
        self.assertEqual(result["counts"], {"UNKNOWN": 2})

    def test_purl_without_location_is_not_target_binding(self):
        self.document["components"][0].pop("properties")
        self.observed()
        self.assertEqual(self.execute()["counts"], {"UNKNOWN": 1})

    def test_source_or_vendored_location_never_becomes_installed(self):
        self.document["components"][0]["properties"][0]["value"] = "src/vendor/alpha-1.dist-info/METADATA"
        self.observed()
        self.assertEqual(self.execute()["counts"], {"UNKNOWN": 1})

    def test_malformed_requirement_cannot_prove_absence(self):
        self.put("alpha", "1", "Requires-Dist: !!!\n")
        self.observed()
        self.assertEqual(self.execute()["counts"], {"UNKNOWN": 1})

    def test_installed_dynamic_field_does_not_disable_local_proof(self):
        self.put("alpha", "1", "Dynamic: Requires-Dist\n")
        self.observed()
        self.assertEqual(self.execute()["counts"], {"REFUTED": 1})

    def test_legacy_requires_cannot_be_closed_as_no_dependencies(self):
        self.put("alpha", "1", "Requires: beta\n")
        self.observed()
        self.assertEqual(self.execute()["counts"], {"UNKNOWN": 1})

    def test_public_metadata_does_not_acquire_target_authority(self):
        self.observed()
        manifest, raw = self.bundle()
        original = next(s for s in manifest.sources if "/alpha-" in s.occurrence_path)
        replacement = original.model_copy(update={"kind": "registry_metadata",
            "source_id": sha(["registry_metadata", manifest.target_id, original.occurrence_path, original.sha256])})
        manifest.sources = [replacement if s == original else s for s in manifest.sources]
        raw[replacement.source_id] = raw.pop(original.source_id)
        result = reconcile_certified(self.document, self.context, manifest, raw)
        self.assertEqual(result["counts"], {"UNKNOWN": 1})

    def test_conflicting_unread_claim_does_not_close_inventory(self):
        self.put("alpha", "1", 'Requires-Dist: beta; extra == "optional"\n')
        self.observed()
        manifest, raw = self.bundle()
        source = next(s for s in manifest.sources if "/alpha-" in s.occurrence_path)
        changed_hash = "1" * 64
        alternative = source.model_copy(update={"acquired": False, "sha256": changed_hash,
            "source_id": sha([source.kind, manifest.target_id, source.occurrence_path, changed_hash]),
            "path": "sources/not-acquired.metadata"})
        manifest.sources.append(alternative)
        self.assertEqual(reconcile_certified(self.document, self.context, manifest, raw)["counts"], {"CONFLICT": 1})

    def test_collector_and_bundle_reject_symlink_and_traversal(self):
        manifest, _ = self.bundle()
        source = manifest.sources[0]
        bad = manifest.model_dump()
        bad["sources"][0]["path"] = "../oracle/labels.json"
        with self.assertRaises(ValueError):
            EvidenceManifestV2.model_validate(bad)
        path = self.target / source.occurrence_path
        path.unlink()
        path.symlink_to(self.target / next(s.occurrence_path for s in manifest.sources if s != source))
        with self.assertRaises(ValueError):
            collect_evidence(self.document, self.context, self.target, "2026-11-08T00:00:00Z", self.root / "bad-evidence")

    def test_checker_is_on_application_path(self):
        from unittest.mock import patch
        manifest, raw = self.bundle()
        decisions, diagnostics = propose(self.document, self.context, manifest, raw)
        decisions[0].certificate.requirement_indices = [999]
        before = deepcopy(self.document)
        with patch("sbom_recovery.reconciliation.certified_reconciliation.propose", return_value=(decisions, diagnostics)):
            with self.assertRaises(ValueError):
                reconcile_certified(self.document, self.context, manifest, raw)
        self.assertEqual(self.document, before)

    def test_active_and_inactive_matching_declarations_keep_edge(self):
        self.put("alpha", "1", 'Requires-Dist: beta; extra == "optional"\nRequires-Dist: beta>=2\n')
        self.observed()
        self.assertEqual(self.execute()["counts"], {"SUPPORTED": 1})

    def test_version_mismatch_and_direct_url_abstain(self):
        for requirement in ("beta<2", "beta @ https://example.invalid/beta.whl"):
            with self.subTest(requirement=requirement):
                self.put("alpha", "1", f"Requires-Dist: {requirement}\n")
                self.document["dependencies"] = []
                self.observed()
                self.assertEqual(self.execute()["counts"], {"UNKNOWN": 1})

    def test_conflicting_bytes_for_same_occurrence_abstain(self):
        self.observed()
        manifest, raw = self.bundle()
        source = next(s for s in manifest.sources if "/alpha-" in s.occurrence_path)
        replacement = raw[source.source_id].replace(b"beta>=2", b"beta>=3")
        digest = hashlib.sha256(replacement).hexdigest()
        sid = sha([source.kind, manifest.target_id, source.occurrence_path, digest])
        second = source.model_copy(update={"source_id": sid, "sha256": digest, "bytes": len(replacement), "path": "sources/other.metadata"})
        manifest.sources.append(second)
        raw[sid] = replacement
        result = reconcile_certified(self.document, self.context, manifest, raw)
        self.assertEqual(result["counts"], {"CONFLICT": 1})
        self.assertEqual(NativeDocument(result["document"]).edges(), {("alpha", "beta")})

    def test_wrong_target_future_evidence_and_changed_bytes_are_rejected(self):
        manifest, raw = self.bundle()
        source = manifest.sources[0]
        for bad in (manifest.model_copy(update={"target_id": "other"}),
                    manifest.model_copy(update={"observation_sha256": "0" * 64})):
            with self.assertRaises(ValueError):
                reconcile_certified(self.document, self.context, bad, raw)
        source.available_at = "2027-01-01T00:00:00Z"
        with self.assertRaises(ValueError):
            reconcile_certified(self.document, self.context, manifest, raw)
        manifest, raw = self.bundle()
        raw[next(iter(raw))] += b"changed"
        with self.assertRaises(ValueError):
            reconcile_certified(self.document, self.context, manifest, raw)

    def test_rejects_forged_citation_completeness_and_input(self):
        self.put("alpha", "1", "")
        self.observed()
        manifest, raw = self.bundle()
        decisions, _ = propose(self.document, self.context, manifest, raw)
        original = decisions[0].model_dump()
        for field, value in (("requirement_indices", [99]), ("completeness", []), ("input_sha256", "0" * 64)):
            bad = deepcopy(original)
            bad["certificate"][field] = value
            with self.assertRaises(ValueError, msg=field):
                check_decision(self.document, self.context, manifest, raw, bad)

    def test_checker_rejects_activation_proof_with_omitted_parent_step(self):
        self.put("alpha", "1", "Requires-Dist: beta[optional]\n")
        self.put("beta", "2", 'Requires-Dist: unrelated; extra == "optional"\n')
        manifest, raw = self.bundle()
        decisions, _ = propose(self.document, self.context, manifest, raw)
        bad = next(d.model_dump() for d in decisions if d.source_ref == "beta")
        bad["certificate"]["activation_steps"] = []
        with self.assertRaises(ValueError):
            check_decision(self.document, self.context, manifest, raw, bad)

    def test_checker_rejects_upper_bound_omitting_activation(self):
        self.put("alpha", "1", "Requires-Dist: beta[optional]\n")
        self.put("beta", "2", 'Requires-Dist: unrelated; extra == "optional"\n')
        self.observed("beta", "unrelated")
        manifest, raw = self.bundle()
        key = next(k for k, d in EvidenceView(self.document, self.context, manifest, raw).distributions.items() if d.name == "beta")
        # Fabricate a negative certificate by repurposing a valid positive one.
        decisions, _ = propose(self.document, self.context, manifest, raw)
        bad = next(d.model_dump() for d in decisions if d.source_ref == "beta")
        bad.update(operation="retract", status="REFUTED")
        cert = bad["certificate"]
        cert.update(rule="ALL_MATCHING_DECLARATIONS_INACTIVE", activation_steps=[],
                    activation_upper={k: [] for k in EvidenceView(self.document, self.context, manifest, raw).inventory},
                    completeness=[{"occurrence_id": key, "source_id": next(s.source_id for s in manifest.sources if "/beta-" in s.occurrence_path)}])
        with self.assertRaises(ValueError):
            check_decision(self.document, self.context, manifest, raw, bad)

    def test_unknown_context_is_observationally_nonidentifiable(self):
        self.put("alpha", "1", 'Requires-Dist: beta; extra == "optional"\n')
        self.observed()
        manifest, raw = self.bundle(complete=False)
        uncertain = reconcile_certified(self.document, self.context, manifest, raw)
        alpha = next(v for k, v in manifest.bindings.items() if k == "alpha")
        on = self.context.model_copy(update={"root_requests_complete": True, "root_requests": {alpha: ["optional"]}})
        off = self.context.model_copy(update={"root_requests_complete": True, "root_requests": {}})
        self.assertEqual(uncertain["counts"], {"UNKNOWN": 1})
        self.assertEqual(reconcile_certified(self.document, on, manifest, raw)["counts"], {"SUPPORTED": 1})
        self.assertEqual(reconcile_certified(self.document, off, manifest, raw)["counts"], {"REFUTED": 1})

    def test_spdx_inverse_retraction_preserves_containment(self):
        self.put("alpha", "1", "")
        self.document = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": [
            {"SPDXID": c["bom-ref"], "name": c["name"], "versionInfo": c["version"],
             "externalRefs": [{"referenceType": "purl", "referenceLocator": c["purl"]}]}
            for c in self.document["components"]], "files": [
            {"SPDXID": "file-" + c["bom-ref"], "fileName": c["properties"][0]["value"]}
            for c in self.document["components"]], "relationships": [
            {"spdxElementId": c["bom-ref"], "relatedSpdxElement": "file-" + c["bom-ref"], "relationshipType": "CONTAINS"}
            for c in self.document["components"]]}
        self.document["relationships"].append({"spdxElementId": "beta", "relatedSpdxElement": "alpha", "relationshipType": "DEPENDENCY_OF"})
        result = self.execute()
        self.assertFalse(NativeDocument(result["document"]).edges())
        self.assertEqual(len(result["document"]["relationships"]), 3)
        # Intentionally minimal SPDX controls cannot pass full native validation.
        self.assertFalse(result["validation"]["valid"])

    def test_syft_spdx_source_info_binds_without_contains_edges(self):
        self.put("alpha", "1", "")
        self.document = {"spdxVersion": "SPDX-2.3", "packages": [
            {"SPDXID": c["bom-ref"], "name": c["name"], "versionInfo": c["version"],
             "sourceInfo": "acquired package info from installed python package manifest file: /" +
                           c["properties"][0]["value"] + ", /other/RECORD",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": c["purl"]}]}
            for c in self.document["components"]], "relationships": [
            {"spdxElementId": "alpha", "relatedSpdxElement": "beta", "relationshipType": "DEPENDS_ON"}]}
        self.assertEqual(self.execute()["counts"], {"REFUTED": 1})
        self.document["packages"][0]["sourceInfo"] = "not a locator: " + self.document["packages"][0]["sourceInfo"]
        self.assertEqual(self.execute()["counts"], {"UNKNOWN": 1})

    def test_replaying_checked_result_is_semantically_idempotent(self):
        result = self.execute()
        self.document = result["document"]
        repeated = self.execute()
        self.assertEqual(repeated["document"], self.document)
        self.assertEqual(repeated["operations"], {"keep": 1})

    def test_cli_collect_reconcile_and_reject_existing_output(self):
        self.put("alpha", "1", "")
        self.observed()
        self.bundle()
        inp, ctx = self.root / "input.json", self.root / "context.json"
        inp.write_text(json.dumps(self.document))
        ctx.write_text(self.context.model_dump_json())
        evidence, output = self.root / "cli-evidence", self.root / "cli-output"
        base = [sys.executable, "-B", "-m", "sbom_recovery"]
        collected = subprocess.run(base + ["reconcile-collect", "--input", str(inp), "--context", str(ctx),
            "--target", str(self.target), "--available-at", "2026-11-08T00:00:00Z", "--out", str(evidence)],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(collected.returncode, 0, collected.stderr)
        args = ["reconcile", "--input", str(inp), "--context", str(ctx), "--evidence", str(evidence / "manifest.json"), "--out", str(output)]
        result = subprocess.run(base + args, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "observation.json").read_bytes(), inp.read_bytes())
        self.assertTrue(json.loads((output / "seal.json").read_text())["reference_labels_read"] is False)
        self.assertTrue(json.loads(result.stdout)["valid"])
        with self.assertRaises(FileExistsError):
            run(inp, ctx, evidence / "manifest.json", output)


class MarkerAbstractionTests(unittest.TestCase):
    def test_bounds_against_exhaustive_completions(self):
        expressions = [
            'sys_platform == "linux"',
            'sys_platform == "win32" and platform_release == "x"',
            'sys_platform == "linux" or platform_release == "x"',
            'extra == "a"', 'extra != "a"',
            'extra == "a" and extra == "b"',
            '(extra == "a" or extra == "b") and sys_platform == "linux"',
        ]
        # Exact finite truth is computed by packaging on each complete context,
        # not by the abstract evaluator or reconciliation implementation.
        for expression, platform, known, possible in itertools.product(
                expressions, [None, "linux", "win32"], [set(), {"a"}], [None, {"a", "b"}]):
            req = Requirement("beta; " + expression)
            ctx = ContextKnowledgeV2(target_id="test", installation_scope=INSTALLATION,
                evidence_cutoff="2026-11-09T00:00:00Z", marker_values={"sys_platform": platform})
            bound = marker_bounds(req, ctx, known, possible)
            truths = []
            for os_value, release, mask in itertools.product(["linux", "win32"], ["x", "y"], range(4)):
                if platform is not None and platform != os_value:
                    continue
                extras = {e for i, e in enumerate(["a", "b"]) if mask & (1 << i)}
                if not known <= extras or (possible is not None and not extras <= possible):
                    continue
                truths.append(any(req.marker.evaluate(environment={"sys_platform": os_value,
                    "platform_release": release, "extra": e}) for e in extras | {""}))
            with self.subTest(expression=expression, platform=platform, known=known, possible=possible):
                if bound is True:
                    self.assertTrue(all(truths))
                elif bound is False:
                    self.assertFalse(any(truths))

    def test_fixed_point_decisions_against_small_world_enumeration(self):
        """432 abstract cases, checked against all compatible finite worlds.

        Concrete activation is implemented by Boolean rules on a 3-cycle, without
        using packaging, marker_bounds, activation_bounds or the checker.
        """
        names = ["a", "b", "c"]
        target_id = "finite-world-enumeration"
        expressions = {"always": "", "extra": '; extra == "opt"', "windows": '; sys_platform == "win32"'}
        for guards, seed_mask, platform, complete in itertools.product(
                itertools.product(expressions, repeat=3), range(4), ["linux", None], [True, False]):
            document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                        "components": [], "dependencies": []}
            sources, bindings, raw, keys = [], {}, {}, []
            for i, name in enumerate(names):
                child = names[(i + 1) % 3]
                path = f"{INSTALLATION}/{name}-1.dist-info/METADATA"
                key = occurrence_id(target_id, path)
                keys.append(key)
                content = f"Metadata-Version: 2.3\nName: {name}\nVersion: 1\nRequires-Dist: {child}[opt]{expressions[guards[i]]}\n\n".encode()
                digest = hashlib.sha256(content).hexdigest()
                sid = sha(["installed_metadata", target_id, path, digest])
                sources.append(EvidenceSourceV2(source_id=sid, path=f"sources/{sid}.metadata", occurrence_path=path,
                    sha256=digest, bytes=len(content), available_at="2026-11-08T00:00:00Z"))
                raw[sid], bindings[name] = content, key
                document["components"].append({"type": "library", "bom-ref": name, "name": name,
                    "version": "1", "purl": f"pkg:pypi/{name}@1",
                    "properties": [{"name": "sbom-recovery:metadata-path", "value": path}]})
                document["dependencies"].append({"ref": name, "dependsOn": [child]})
            seed = {i for i in range(3) if seed_mask & (1 << i)}
            context = ContextKnowledgeV2(target_id=target_id, installation_scope=INSTALLATION,
                evidence_cutoff="2026-11-09T00:00:00Z", marker_values={"sys_platform": platform},
                root_requests={keys[i]: ["opt"] for i in seed}, root_requests_complete=complete)
            manifest = EvidenceManifestV2(target_id=target_id, observation_sha256=sha(document),
                inventory_complete=True, sources=sources, bindings=bindings)
            worlds = []
            for actual_mask, actual_platform in itertools.product(range(8), ["linux", "win32"]):
                actual_seed = {i for i in range(3) if actual_mask & (1 << i)}
                if (not seed <= actual_seed or (complete and seed != actual_seed)
                        or (platform is not None and platform != actual_platform)):
                    continue
                active = set(actual_seed)
                def enabled(index):
                    return (guards[index] == "always" or guards[index] == "extra" and index in active
                            or guards[index] == "windows" and actual_platform == "win32")
                while True:
                    propagated = active | {(i + 1) % 3 for i in range(3) if enabled(i)}
                    if propagated == active:
                        break
                    active = propagated
                worlds.append({(names[i], names[(i + 1) % 3]) for i in range(3) if enabled(i)})
            decisions, _ = propose(document, context, manifest, raw)
            check_decisions(document, context, manifest, raw, decisions)
            self.assertTrue(worlds)
            for d in decisions:
                edge = d.source_ref, d.target_ref
                if d.status == "SUPPORTED":
                    self.assertTrue(all(edge in world for world in worlds), (guards, seed_mask, platform, complete, d))
                elif d.status == "REFUTED":
                    self.assertTrue(all(edge not in world for world in worlds), (guards, seed_mask, platform, complete, d))
            # Deliberately allow the strong semantic control to tie the method.
            control = metadata_control(document, context, manifest, raw)
            expected = NativeDocument(document).edges() - {(d.source_ref, d.target_ref) for d in decisions if d.operation == "retract"}
            self.assertEqual(NativeDocument(control).edges(), expected)


if __name__ == "__main__":
    unittest.main()
