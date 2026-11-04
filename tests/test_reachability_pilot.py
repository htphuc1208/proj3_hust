"""Scientific boundaries: static presence, input execution and fault evidence."""
import copy
import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest

from sbom_recovery.reachability_pilot import (
    extract_yaml, matching_audit, runtime_assessment, shortest_path,
    source_member, static_assessment,
)
from sbom_recovery.reachability_worker import PAYLOAD


def witness():
    signature = {"bytecode": "fixed-code", "constants": "(42,)", "names": []}
    stack = [{"file": "yaml/constructor.py", "function": "FullConstructor.make_python_instance"}]
    return {"status": "COMPLETE", "is_arithmetic_tuple": True, "error": None,
            "input_kind": "arithmetic", "input_sha256": hashlib.sha256(PAYLOAD.encode()).hexdigest(),
            "expected_code_signature": signature, "audit_events": [
                {"event": "compile", "source_sha256": hashlib.sha256(b"40 + 2").hexdigest(), "stack": stack},
                {"event": "exec", "signature": signature, "stack": stack}],
            "python_calls": [{"file": "yaml/constructor.py", "function": "FullConstructor.construct_python_object_new"}]}


class ReachabilityBoundaryTests(unittest.TestCase):
    def test_discovered_but_disconnected_constructor_is_not_reachable(self):
        graph = {"app.entry": ["yaml.load"], "yaml.load": [], "unrelated": ["constructor"], "constructor": []}
        self.assertIsNone(shortest_path(graph, "app.entry", "constructor"))
        self.assertEqual(shortest_path(graph, "app.entry", "yaml.load"), ["app.entry", "yaml.load"])

    def test_source_presence_does_not_repair_analyzer_paths(self):
        config = {"entry_symbol": "app.entry", "api_symbol": "yaml.load", "patch_linked_symbol": "yaml.constructor.sink"}
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "app.py").write_text("def entry(text):\n    return text\n")
            result = static_assessment({"status": "COMPLETE", "graph": {"app.entry": []}}, config, directory)
        self.assertEqual(result["constructor_path"]["status"], "UNKNOWN")
        self.assertEqual(result["api_path"]["status"], "UNKNOWN")

    def test_loader_entry_and_tuple_result_alone_do_not_prove_fault(self):
        raw = witness(); raw["audit_events"] = []
        result = runtime_assessment(raw, instrumentation_valid=True)
        self.assertEqual(result["dynamic_function_entry"]["status"], "OBSERVED")
        self.assertEqual(result["fault_witness"], "NOT_OBSERVED_FOR_THIS_INPUT")

    def test_matching_compilation_execution_and_result_are_required(self):
        raw = witness()
        self.assertEqual(runtime_assessment(raw, instrumentation_valid=True)["fault_witness"], "BENIGN_FAULT_WITNESSED")
        for field, value in [("is_arithmetic_tuple", False), ("input_kind", "ordinary"), ("input_sha256", "different")]:
            changed = copy.deepcopy(raw); changed[field] = value
            self.assertEqual(runtime_assessment(changed, instrumentation_valid=True)["fault_witness"], "NOT_OBSERVED_FOR_THIS_INPUT")
        for events in [raw["audit_events"][::-1], raw["audit_events"][:1], raw["audit_events"][1:]]:
            changed = dict(raw, audit_events=events)
            self.assertFalse(matching_audit(changed, require_library_stack=True))

    def test_outside_eval_and_wrong_expression_cannot_count_as_library_fault(self):
        raw = witness()
        raw["audit_events"][0]["stack"] = []
        self.assertFalse(matching_audit(raw, require_library_stack=True))
        raw = witness();raw["audit_events"][0]["source_sha256"] = hashlib.sha256(b"41+1").hexdigest()
        self.assertFalse(matching_audit(raw, require_library_stack=True))

    def test_instrumentation_failure_and_execution_failure_abstain(self):
        self.assertEqual(runtime_assessment(witness(), instrumentation_valid=False)["fault_witness"], "UNKNOWN")
        self.assertEqual(runtime_assessment({"status": "CONTAINER_ERROR"}, instrumentation_valid=True)["fault_witness"], "UNKNOWN")
        self.assertEqual(runtime_assessment(dict(witness(), error={"type": "TypeError"}), instrumentation_valid=True)["fault_witness"], "UNKNOWN")

    def test_absent_fault_never_changes_product_vex_to_unaffected(self):
        for raw in [witness(), {"status": "COMPLETE"}, {"status": "EXECUTION_ERROR"}]:
            self.assertEqual(runtime_assessment(raw, instrumentation_valid=True)["product_vex"], "under_investigation")

    def test_archive_traversal_and_source_links_are_rejected(self):
        for name in ["../yaml/constructor.py", "/yaml/a.py", "x/../a.py", "x//a.py", "x\\a.py"]:
            with self.subTest(name=name), self.assertRaises(ValueError): source_member(name)
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory, "source.tar.gz")
            with tarfile.open(archive, "w:gz") as stream:
                entry = tarfile.TarInfo("release/lib3/yaml/constructor.py")
                entry.type = tarfile.SYMTYPE;entry.linkname = "/etc/passwd"
                stream.addfile(entry)
            with self.assertRaises(ValueError): extract_yaml(archive, Path(directory, "yaml"))

    def test_exec_signature_requires_matching_compile_flags(self):
        """Regression: future annotations in worker must not affect expected signature."""
        raw = witness()
        # Simulate exec with different compile flags (e.g., inherited future flags)
        mismatched_signature = dict(raw["expected_code_signature"], flags=16777216)
        raw["audit_events"][1]["signature"] = mismatched_signature
        raw["audit_events"][1]["matches_expected"] = False
        # Should not match even though bytecode/constants are same
        self.assertFalse(matching_audit(raw, require_library_stack=True))


if __name__ == "__main__": unittest.main()
