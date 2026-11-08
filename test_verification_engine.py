#!/usr/bin/env python3
"""
Project Zero-Day - Milestone 2: Evidence Verification Unit Test Suite
Script: test_verification_engine.py
Objective: Verify genuine evidence verification with 4-state taxonomy:
           1. CONFIRMED: Verified by defensive read-only assertions (e.g. absent CSP, Swagger endpoint).
           2. REJECTED: Contradicted by probe (e.g. X-Frame-Options present on server).
           3. MANUAL_REVIEW: High-severity injection / dangerous functions requiring human review.
           4. NEEDS_VERIFICATION: Unprobed or out-of-scope fixtures.
"""

import json
import tempfile
import unittest
from pathlib import Path

from app.verification_engine import (
    evaluate_finding_verification,
    run_verification_engine,
    verify_finding_evidence,
    VALID_VERIFICATION_STATUSES,
)
from app.orchestrator import PolicyGate


class TestVerificationEngine(unittest.TestCase):
    """
    Unit test suite covering the 4-state verification engine.
    """

    def setUp(self):
        self.policy_gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    def test_01_confirmed_missing_header_live(self):
        """
        Verify that missing Content-Security-Policy header on Juice Shop is CONFIRMED.
        """
        finding = {
            "id": "TEST-CSP-001",
            "title": "Content Security Policy (CSP) Header Not Set",
            "cwe_id": "CWE-693",
            "affected_asset": {"url": "http://localhost:3000"},
        }
        verif = verify_finding_evidence(finding, target_base_url="http://localhost:3000", policy_gate=self.policy_gate)
        self.assertEqual(verif["status"], "CONFIRMED")
        self.assertTrue(verif["verified"])
        self.assertEqual(verif["verification_method"], "defensive_header_assertion")
        self.assertIn("evidence_hash", verif["evidence"])
        self.assertIn("Content-Security-Policy", verif["evidence"]["missing_header"])

    def test_02_rejected_present_header_live(self):
        """
        Verify that claimed missing X-Frame-Options is REJECTED because Juice Shop sets SAMEORIGIN.
        """
        finding = {
            "id": "TEST-XFO-001",
            "title": "X-Frame-Options Header Not Set",
            "cwe_id": "CWE-1021",
            "affected_asset": {"url": "http://localhost:3000"},
        }
        verif = verify_finding_evidence(finding, target_base_url="http://localhost:3000", policy_gate=self.policy_gate)
        self.assertEqual(verif["status"], "REJECTED")
        self.assertFalse(verif["verified"])
        self.assertEqual(verif["verification_method"], "defensive_header_assertion")
        self.assertIn("SAMEORIGIN", verif["evaluation_notes"])

    def test_03_confirmed_exposed_swagger_route(self):
        """
        Verify that public Swagger documentation at /api-docs/swagger.json is CONFIRMED.
        """
        finding = {
            "id": "TEST-SWAGGER-001",
            "title": "Public Swagger API - Detect",
            "cwe_id": "CWE-200",
            "affected_asset": {"url": "http://localhost:3000/api-docs/swagger.json"},
        }
        verif = verify_finding_evidence(finding, target_base_url="http://localhost:3000", policy_gate=self.policy_gate)
        self.assertEqual(verif["status"], "CONFIRMED")
        self.assertTrue(verif["verified"])
        self.assertEqual(verif["verification_method"], "defensive_route_assertion")
        self.assertEqual(verif["evidence"]["http_status"], 200)

    def test_04_manual_review_injection_safety_invariant(self):
        """
        Verify that SQL Injection and XSS are strictly routed to MANUAL_REVIEW.
        """
        findings = [
            {"id": "TEST-SQLI", "title": "SQL Injection", "cwe_id": "CWE-89", "affected_asset": {"url": "http://localhost:3000/api/items"}},
            {"id": "TEST-XSS", "title": "Cross Site Scripting (Reflected)", "cwe_id": "CWE-79", "affected_asset": {"url": "http://localhost:3000/search"}},
            {"id": "TEST-DANGEROUS", "title": "Dangerous JS Functions", "cwe_id": "CWE-749", "affected_asset": {"url": "http://localhost:3000/main.js"}},
        ]
        for f in findings:
            verif = verify_finding_evidence(f, target_base_url="http://localhost:3000", policy_gate=self.policy_gate)
            self.assertEqual(verif["status"], "MANUAL_REVIEW", f"Expected MANUAL_REVIEW for {f['title']}")
            self.assertFalse(verif["verified"])
            self.assertEqual(verif["verification_method"], "safety_gate_manual_review")
            self.assertIn("manual review", verif["evaluation_notes"].lower())

    def test_05_needs_verification_out_of_scope(self):
        """
        Verify that out-of-scope targets are denied probing and remain NEEDS_VERIFICATION.
        """
        finding = {
            "id": "TEST-OUT-OF-SCOPE",
            "title": "Content Security Policy (CSP) Header Not Set",
            "cwe_id": "CWE-693",
            "affected_asset": {"url": "http://target.local:80/index.html"},
        }
        verif = verify_finding_evidence(finding, policy_gate=self.policy_gate)
        self.assertEqual(verif["status"], "NEEDS_VERIFICATION")
        self.assertFalse(verif["verified"])
        self.assertEqual(verif["verification_method"], "policy_scope_invariant")

    def test_06_offline_mode_preserves_needs_verification(self):
        """
        Verify that offline/sample mode evaluates all findings into NEEDS_VERIFICATION.
        """
        finding = {
            "id": "TEST-SAMPLE",
            "title": "Content Security Policy (CSP) Header Not Set",
            "cwe_id": "CWE-693",
            "affected_asset": {"url": "http://localhost:3000"},
        }
        evaluated = evaluate_finding_verification(finding, live_verification=False)
        self.assertEqual(evaluated["verification"]["status"], "NEEDS_VERIFICATION")
        self.assertFalse(evaluated["verification"]["verified"])

    def test_07_run_verification_engine_batch(self):
        """
        Verify batch execution through run_verification_engine writes valid output.
        """
        test_findings = [
            {"id": "F-01", "title": "Content Security Policy (CSP) Header Not Set", "cwe_id": "CWE-693", "affected_asset": {"url": "http://localhost:3000"}},
            {"id": "F-02", "title": "X-Frame-Options Header Not Set", "cwe_id": "CWE-1021", "affected_asset": {"url": "http://localhost:3000"}},
            {"id": "F-03", "title": "SQL Injection", "cwe_id": "CWE-89", "affected_asset": {"url": "http://localhost:3000/api"}},
            {"id": "F-04", "title": "Cacheable Content", "cwe_id": "CWE-524", "affected_asset": {"url": "http://localhost:3000/static"}},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "input.json"
            output_file = Path(tmpdir) / "output.json"
            with open(input_file, "w", encoding="utf-8") as f:
                json.dump(test_findings, f)

            results = run_verification_engine(
                input_path=input_file,
                output_path=output_file,
                live_verification=True,
                target_url="http://localhost:3000",
                policy_gate=self.policy_gate,
            )
            self.assertEqual(len(results), 4)
            statuses = {r["verification"]["status"] for r in results}
            self.assertTrue(statuses.issubset(VALID_VERIFICATION_STATUSES))
            self.assertIn("CONFIRMED", statuses)
            self.assertIn("REJECTED", statuses)
            self.assertIn("MANUAL_REVIEW", statuses)
            self.assertIn("NEEDS_VERIFICATION", statuses)


if __name__ == "__main__":
    unittest.main()
