"""Evaluation-boundary regressions for the exploratory paper-corpus probes."""
from copy import deepcopy
import unittest

from scripts.analyze_paper_corpus_probe import declaration_graph, sbom_facts


def inventory(a_requirements, b_requirements=(), b_origin=None):
    return dict(environment={"sys_platform": "linux", "python_version": "3.11"}, distributions=[
        dict(name="a", version="1", requirements=list(a_requirements), direct_url=None),
        dict(name="b", version="2", requirements=list(b_requirements), direct_url=b_origin),
        dict(name="c", version="3", requirements=[], direct_url=None)])


class PaperCorpusEvaluationTests(unittest.TestCase):
    def test_installed_child_does_not_activate_parent_extra(self):
        probe = inventory(['b; extra == "opt"'])
        self.assertEqual(declaration_graph(probe)[1], set())
        self.assertEqual(declaration_graph(probe, {"a": ["opt"]})[1], {("a", "b")})

    def test_child_extra_propagates_from_active_requirement(self):
        probe = inventory(["b[opt]>=2"], ['c; extra == "opt"'])
        self.assertEqual(declaration_graph(probe)[1], {("a", "b"), ("b", "c")})

    def test_known_false_platform_marker_stays_inactive(self):
        probe = inventory(['b; sys_platform == "win32"'])
        self.assertEqual(declaration_graph(probe)[1], set())

    def test_url_binding_requires_installed_origin(self):
        url = "https://example.invalid/b-2.tar.gz"
        probe = inventory(["b @ " + url])
        self.assertTrue(declaration_graph(probe)[2])
        probe["distributions"][1]["direct_url"] = {"url": url}
        self.assertEqual(declaration_graph(probe)[1], {("a", "b")})
        probe["distributions"][1]["direct_url"] = {"url": url + ".different"}
        self.assertTrue(declaration_graph(probe)[2])

    def test_git_tag_requires_matching_revision_or_archived_tag_binding(self):
        repo = "https://example.invalid/b.git"
        probe = inventory(["b @ git+" + repo + "@tag"], b_origin={"url": repo,
            "vcs_info": {"commit_id": "commit", "requested_revision": "commit"}})
        self.assertTrue(declaration_graph(probe)[2])
        self.assertEqual(declaration_graph(probe, git_bindings={repo + "@tag": "commit"})[1], {("a", "b")})
        self.assertTrue(declaration_graph(probe, git_bindings={repo + "@tag": "other"})[2])
        probe["distributions"][1]["direct_url"] = {"url": repo}
        self.assertTrue(declaration_graph(probe)[2])

    def test_sbom_parser_keeps_root_topology_without_inventing_version(self):
        document = dict(metadata={"component": {"bom-ref": "root", "name": "a"}},
            components=[{"bom-ref": "b", "name": "B", "version": "2", "purl": "pkg:pypi/b@2"}],
            dependencies=[{"ref": "root", "dependsOn": ["b", "absent"]}])
        before = deepcopy(document)
        components, packages, edges, dangling = sbom_facts(document)
        self.assertEqual(edges, {("a", "b")})
        self.assertEqual(dangling, [("root", "absent")])
        self.assertEqual(len(packages), 1)
        self.assertNotIn("version", components[-1])
        self.assertEqual(document, before)


if __name__ == "__main__":
    unittest.main()
