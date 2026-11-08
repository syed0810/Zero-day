#!/usr/bin/env python3
"""
Unit and Invariant Tests for the Decision Policy Model
Script: test_decision_policy_model.py
Objective: Verify real predictive behavior, defensive rule layer invariants,
           ZAP vocabulary normalization, and fallback mechanisms without
           external fixture dependencies.
"""

import json
import tempfile
import unittest
from pathlib import Path

from decision_engine import VALID_ACTIONS, run_decision_engine
from policy_model import DecisionPolicyModel, get_policy_model, CONFIDENCE_THRESHOLD

PROJECT_ROOT = Path(__file__).resolve().parent


class TestDecisionPolicyModel(unittest.TestCase):
    """
    Test suite verifying real predictive behavior and defensive rule invariants.
    """

    @classmethod
    def setUpClass(cls):
        cls.model = get_policy_model()

    def test_01_model_loading_and_sha256(self):
        """Verify model artifact exists, loads cleanly, and passes SHA-256 integrity check."""
        self.assertTrue(self.model.is_loaded, "Decision policy model must be loaded.")
        self.assertTrue(self.model.sha256_verified, "Model SHA-256 signature must be verified against metadata.")
        self.assertIsNotNone(self.model.pipeline, "Model pipeline must not be None.")

    def test_02_predictive_behavior_by_severity_and_class(self):
        """
        Assert REAL behavior: Severity and vulnerability class actively determine actions.
        High/Critical injection without evidence -> collect_more_evidence.
        Low/Info hardening with evidence -> recommend_remediation.
        """
        sqli_finding = {
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "risk_rating": "Critical",
            "source_type": "web",
            "evidence": {"evidence": ""},
        }
        csp_finding = {
            "title": "Content Security Policy (CSP) Header Not Set",
            "cwe_id": "CWE-693",
            "risk_rating": "Low",
            "source_type": "web",
            "evidence": {"evidence": "CSP header missing on HTTP 200 response"},
        }

        action_sqli, conf_sqli = self.model.predict_action_with_confidence(sqli_finding)
        action_csp, conf_csp = self.model.predict_action_with_confidence(csp_finding)

        # Real behavioral assertions: Critical SQLi vs Low CSP must NOT receive identical actions
        self.assertEqual(action_sqli, "collect_more_evidence", "Unproved critical SQLi must demand evidence collection.")
        self.assertEqual(action_csp, "recommend_remediation", "Evidenced low-risk CSP header check must route to remediation.")
        self.assertNotEqual(action_sqli, action_csp, "Severity and class must produce distinct tactical actions.")

    def test_03_invariant_no_remediation_without_evidence(self):
        """
        Rule Invariant 1: No recommend_remediation without evidence.
        If a finding has zero evidence, the rule layer must prevent premature remediation.
        """
        unevidenced_finding = {
            "title": "Potential Missing Header",
            "cwe_id": "CWE-693",
            "risk_rating": "Low",
            "source_type": "web",
            "evidence": {"attack": "", "evidence": "", "raw_payload": ""},
        }
        action, _ = self.model.predict_action_with_confidence(unevidenced_finding)
        self.assertNotEqual(
            action,
            "recommend_remediation",
            "Defensive Invariant Violated: Model recommended remediation without evidence."
        )
        self.assertIn(action, ["collect_more_evidence", "inspect_related_endpoint"])

    def test_04_invariant_failed_prior_action_escalates(self):
        """
        Rule Invariant 2: Failed prior action must trigger tactical escalation.
        """
        finding = {
            "title": "Authentication Bypass Attempt",
            "cwe_id": "CWE-287",
            "risk_rating": "High",
            "source_type": "web",
            "evidence": {"evidence": "Authentication token was rejected"},
        }
        action, conf = self.model.predict_action_with_confidence(
            finding,
            prior_action_failed=True,
        )
        self.assertEqual(conf, 1.0)
        self.assertIn(action, ["manual_review", "inspect_related_endpoint"])

    def test_05_invariant_low_confidence_escalates_to_manual_review(self):
        """
        Rule Invariant 3: Low confidence predictions (< 0.50) must escalate to manual_review.
        """
        ambiguous_finding = {
            "title": "Unclassified Novel Zero-Day Kernel Artifact",
            "cwe_id": "CWE-9999",
            "risk_rating": "Unknown",
            "source_type": "quantum_substrate",
        }
        action, conf = self.model.predict_action_with_confidence(ambiguous_finding)
        self.assertLess(conf, CONFIDENCE_THRESHOLD, "OOD input must trigger low model confidence.")
        self.assertEqual(action, "manual_review", "Low confidence prediction must escalate to manual_review.")

    def test_06_fallback_actually_fires(self):
        """
        Verify that fallback mechanism actually triggers when model is missing or corrupt.
        """
        dummy_model = DecisionPolicyModel(
            model_path=PROJECT_ROOT / "non_existent_model.joblib",
            metadata_path=PROJECT_ROOT / "policy_model_metadata.json",
        )
        self.assertFalse(dummy_model.is_loaded)
        action, conf = dummy_model.predict_action_with_confidence(
            {"title": "Test Finding"},
            fallback_action="manual_review",
        )
        self.assertEqual(action, "manual_review")
        self.assertEqual(conf, 0.0)

    def test_07_vocabulary_mapping_zap_findings(self):
        """
        Verify ZAP findings (CSP Not Set, Cookie Without SameSite, Informational severity)
        are normalized into the model's vocabulary and features.
        """
        zap_cookie = {
            "title": "Cookie Without SameSite Attribute",
            "cwe_id": "CWE-1275",
            "risk_rating": "Informational",
            "evidence": {"evidence": "Set-Cookie header missing SameSite attribute"},
        }
        features = self.model.extract_features(zap_cookie)
        self.assertEqual(features["severity"], "informational")
        self.assertEqual(features["severity_weight"], 0)
        self.assertIn("SameSite", features["vulnerability_class"])

    def test_08_decision_engine_standalone_fixture(self):
        """
        Verify decision_engine.py using an inline mock fixture (ZERO dependency on normalized_findings.json on disk).
        """
        mock_findings = [
            {
                "id": "MOCK-001",
                "title": "SQL Injection",
                "cwe_id": "CWE-89",
                "risk_rating": "High",
                "evidence": {"evidence": "syntax error near OR"},
            },
            {
                "id": "MOCK-002",
                "title": "Cookie Without SameSite Attribute",
                "cwe_id": "CWE-1275",
                "risk_rating": "Informational",
                "evidence": {"evidence": "cookie flag missing"},
            },
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            input_file = tmp_path / "mock_input.json"
            output_file = tmp_path / "mock_output.json"

            with open(input_file, "w", encoding="utf-8") as f:
                json.dump(mock_findings, f)

            results = run_decision_engine(input_file, output_file)
            self.assertEqual(len(results), 2)
            for r in results:
                self.assertIn("suggested_action", r)
                self.assertIn(r["suggested_action"], VALID_ACTIONS)
                self.assertIn("priority", r)
                self.assertIn(r["priority"], ["P1", "P2", "P3", "P4"])


if __name__ == "__main__":
    unittest.main()
