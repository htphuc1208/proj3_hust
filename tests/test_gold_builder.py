"""Unit tests for Multi-Ecosystem GoldBuilder."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sbom_recovery.gold_builder import (
    GoldBuilder,
    JavaScriptGoldAdapter,
    JavaGoldAdapter,
    PythonGoldAdapter,
)


class TestGoldBuilder(unittest.TestCase):
    def test_python_gold_adapter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pyproj = Path(tmpdir) / "pyproject.toml"
            pyproj.write_text(
                """
[project]
name = "demo-lib"
version = "1.0.0"
dependencies = [
    "requests>=2.28.0",
    "pydantic",
]
""",
                encoding="utf-8",
            )
            claims = PythonGoldAdapter.extract_g1_manifest(pyproj, "case-py")
            predicates = {c.predicate: c.object for c in claims}
            self.assertEqual(predicates.get("name"), "demo-lib")
            self.assertEqual(predicates.get("version"), "1.0.0")
            dep_claims = [c.object for c in claims if c.predicate == "depends_on"]
            self.assertIn("pkg:pypi/requests", dep_claims)
            self.assertIn("pkg:pypi/pydantic", dep_claims)

    def test_javascript_gold_adapter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_json = Path(tmpdir) / "package.json"
            pkg_json.write_text(
                json.dumps(
                    {
                        "name": "express-demo",
                        "version": "4.18.2",
                        "license": "MIT",
                        "dependencies": {"accepts": "~1.3.8"},
                        "devDependencies": {"mocha": "^10.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            claims = JavaScriptGoldAdapter.extract_g1_manifest(pkg_json, "case-js")
            prod_deps = [c.object for c in claims if c.predicate == "depends_on" and c.scope == "runtime_production"]
            dev_deps = [c.object for c in claims if c.predicate == "depends_on" and c.scope == "development"]
            self.assertIn("pkg:npm/accepts", prod_deps)
            self.assertIn("pkg:npm/mocha", dev_deps)

    def test_java_gold_adapter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pom_xml = Path(tmpdir) / "pom.xml"
            pom_xml.write_text(
                """
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.google.code.gson</groupId>
  <artifactId>gson</artifactId>
  <version>2.10.1</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.google.errorprone</groupId>
      <artifactId>error_prone_annotations</artifactId>
      <version>2.18.0</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
""",
                encoding="utf-8",
            )
            claims = JavaGoldAdapter.extract_g1_manifest(pom_xml, "case-java")
            names = [c.object for c in claims if c.predicate == "name"]
            self.assertIn("com.google.code.gson:gson", names)
            test_deps = [c.object for c in claims if c.predicate == "depends_on" and c.scope == "development"]
            prod_deps = [c.object for c in claims if c.predicate == "depends_on" and c.scope == "runtime_production"]
            self.assertIn("pkg:maven/junit/junit@4.13.2", test_deps)
            self.assertIn("pkg:maven/com.google.errorprone/error_prone_annotations@2.18.0", prod_deps)


if __name__ == "__main__":
    unittest.main()
