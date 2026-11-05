"""Unit tests for pilot audit and claim extraction."""
from __future__ import annotations

import unittest
from sbom_recovery.pilot_audit import extract_claims_from_native


class TestPilotAudit(unittest.TestCase):
    def test_extract_claims_from_spdx(self):
        doc = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "sample",
            "packages": [
                {
                    "name": "requests",
                    "SPDXID": "SPDXRef-Package-requests",
                    "versionInfo": "2.31.0",
                    "licenseDeclared": "Apache-2.0",
                    "downloadLocation": "https://pypi.org/project/requests",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.31.0",
                        }
                    ],
                },
                {
                    "name": "urllib3",
                    "SPDXID": "SPDXRef-Package-urllib3",
                    "versionInfo": "2.0.7",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/urllib3@2.0.7",
                        }
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-Package-requests",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-Package-urllib3",
                }
            ],
        }

        claims = extract_claims_from_native(
            document_data=doc,
            case_id="case-001",
            source_id="test_tool",
            artifact_sha256="abc123",
        )

        predicates = {c.predicate for c in claims}
        self.assertIn("name", predicates)
        self.assertIn("version", predicates)
        self.assertIn("licenseDeclared", predicates)
        self.assertIn("downloadLocation", predicates)
        self.assertIn("depends_on", predicates)

        dep_claims = [c for c in claims if c.predicate == "depends_on"]
        self.assertEqual(len(dep_claims), 1)
        self.assertEqual(dep_claims[0].subject, "pkg:pypi/requests@2.31.0")
        self.assertEqual(dep_claims[0].object, "pkg:pypi/urllib3@2.0.7")


if __name__ == "__main__":
    unittest.main()
