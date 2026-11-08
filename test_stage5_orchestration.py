#!/usr/bin/env python3
"""
Project Zero-Day - Stage 5: Verification & Integration Test Suite
Script: test_stage5_orchestration.py
Objective: Verify all Stage 5 testing requirements:
           1. Orchestrator executes end-to-end with zero unhandled exceptions
           2. decision_log.json contains policy evaluation entries for all processed findings
           3. verification_results.json verifies proper status distribution and defensive invariant
           4. security_report.html renders with complete advisory, provenance, and verification metadata
           5. Zero external CDN dependencies in HTML dashboard (100% offline compliant)
"""

import json
import re
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.orchestrator import MasterOrchestrator
from decision_engine import VALID_ACTIONS


class TestStage5Orchestration(unittest.TestCase):
    """
    Test suite verifying Stage 5 orchestration, policy gate, and dashboard report.
    """

    @classmethod
    def setUpClass(cls):
        cls.orchestrator = MasterOrchestrator(
            workspace_dir=PROJECT_ROOT,
            authorized_scopes=["http://localhost:3000", "localhost:3000", "http://localhost", "localhost"],
            use_sample=True,
        )
        cls.report_data = cls.orchestrator.execute_pipeline()

    def test_01_pipeline_execution_and_deliverables(self):
        """
        Testing Requirement: Master orchestrator runs with zero unhandled exceptions
        and generates all deliverable artifacts.
        """
        self.assertTrue(self.orchestrator.decision_log_file.is_file(), "decision_log.json must exist")
        self.assertTrue(self.orchestrator.verification_file.is_file(), "verification_results.json must exist")
        self.assertTrue(self.orchestrator.report_html_file.is_file(), "security_report.html must exist")
        self.assertTrue(self.orchestrator.report_json_file.is_file(), "security_report.json must exist")
        print("\n[PASS] Test 1: Master orchestrator executed successfully; all deliverables verified.")

    def test_02_decision_log_policy_evaluation(self):
        """
        Testing Requirement: Inspect decision_log.json to confirm policy evaluation
        entries exist for all processed findings.
        """
        with open(self.orchestrator.decision_log_file, "r", encoding="utf-8") as f:
            log_data = json.load(f)

        self.assertIn("decisions", log_data)
        decisions = log_data["decisions"]
        self.assertEqual(len(decisions), 7, f"Expected 7 decision log entries, got {len(decisions)}")

        for d in decisions:
            self.assertIn("finding_id", d)
            self.assertIn("suggested_action", d)
            self.assertIn(d["suggested_action"], VALID_ACTIONS)
            self.assertIn("decision", d)
            self.assertIn(d["decision"], ["ALLOW", "DENY"])
            self.assertIn("reason", d)
            self.assertTrue(len(d["reason"]) > 10)

        print(f"[PASS] Test 2: decision_log.json contains {len(decisions)} policy evaluation entries.")

    def test_03_verification_status_and_hard_invariant(self):
        """
        Testing Requirement: Inspect verification_results.json to verify proper
        status distribution and hard constraint that scanner alerts are never auto-verified.
        """
        with open(self.orchestrator.verification_file, "r", encoding="utf-8") as f:
            verified_findings = json.load(f)

        self.assertEqual(len(verified_findings), 7)
        for f in verified_findings:
            verif = f.get("verification", {})
            self.assertEqual(verif.get("status"), "NEEDS_VERIFICATION")
            self.assertFalse(verif.get("verified"))

        print(f"[PASS] Test 3: Verification status invariant confirmed: 100% NEEDS_VERIFICATION, 0 verified:true.")

    def test_04_html_dashboard_offline_and_provenance(self):
        """
        Testing Requirement: Open security_report.html and verify all normalized findings
        render with complete advisory and verification metadata without CDN dependencies.
        """
        with open(self.orchestrator.report_html_file, "r", encoding="utf-8") as f:
            html_text = f.read()

        # Zero CDN check: ensure no external http/https scripts or stylesheets
        external_links = re.findall(r'<link[^>]+href=[\'"]https?://', html_text)
        external_scripts = re.findall(r'<script[^>]+src=[\'"]https?://', html_text)
        self.assertEqual(len(external_links), 0, f"Found external CDN stylesheets: {external_links}")
        self.assertEqual(len(external_scripts), 0, f"Found external CDN scripts: {external_scripts}")

        # Provenance badge
        self.assertIn("SAMPLE FIXTURE", html_text)

        # Metrics and finding cards
        self.assertIn("P1 (Critical)", html_text)
        self.assertIn("P2 (High)", html_text)
        self.assertTrue(
            "ZAP-40018-fe1cd503" in html_text or "ZAP-40018" in html_text,
            "Expected ZAP-40018 finding in HTML report",
        )
        self.assertIn("SQL Injection", html_text)
        self.assertIn("Gemma AI Security Advisory", html_text)
        self.assertIn("Policy Gate & Tactical Action", html_text)
        self.assertIn("Evidence Verification Status", html_text)

        print("[PASS] Test 4: security_report.html verified: 100% offline, correct provenance, full metadata.")


def run_tests() -> bool:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStage5Orchestration)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
