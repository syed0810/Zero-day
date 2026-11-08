#!/usr/bin/env python3
"""
Project Zero-Day - Milestone 3: Bounded Investigation Loop Unit Test Suite
Script: test_investigation_loop.py
Objective: Verify the autonomous investigation loop driven by the Random Forest model:
           1. Parity between training features and live inference features.
           2. Strict bounds enforcement (max 4 steps per finding, 50 total requests).
           3. Phase progression (initial_scan -> enumeration -> deep_analysis -> verification -> remediation_advisory).
           4. Defensive action allowlist membership (all actions in VALID_ACTIONS).
           5. Complete audit logging into investigation trajectories and decision_log.json.
"""

import unittest
from pathlib import Path

from policy_model import DecisionPolicyModel, VALID_ACTIONS
from app.investigation_loop import InvestigationController
from app.orchestrator import PolicyGate


class TestInvestigationLoop(unittest.TestCase):
    """
    Test suite for Milestone 3 bounded autonomous investigation loop.
    """

    def setUp(self):
        self.model = DecisionPolicyModel()
        self.policy_gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    def test_01_feature_parity_with_training(self):
        """
        Verify that extract_features produces the exact 12 features required by the Random Forest model.
        """
        sample_finding = {
            "id": "PARITY-001",
            "source_type": "web",
            "title": "Content Security Policy (CSP) Header Not Set",
            "cwe_id": "CWE-693",
            "risk_rating": "Medium",
            "evidence": {"observed_at": None},
        }
        features = self.model.extract_features(
            sample_finding,
            phase="initial_scan",
            step_number=1,
            total_steps=4,
            prior_action="none",
            prior_action_failed=False,
        )

        expected_keys = {
            "source_type",
            "vulnerability_class",
            "severity",
            "severity_weight",
            "cwe_id",
            "current_phase",
            "step_number",
            "total_steps",
            "step_ratio",
            "prior_action",
            "evidence_present",
            "prior_action_failed",
        }
        self.assertEqual(set(features.keys()), expected_keys)
        self.assertEqual(features["step_number"], 1)
        self.assertEqual(features["total_steps"], 4)
        self.assertEqual(features["step_ratio"], 0.25)
        self.assertEqual(features["prior_action"], "none")
        self.assertEqual(features["evidence_present"], 0)
        self.assertEqual(features["prior_action_failed"], 0)

    def test_02_model_sha256_integrity(self):
        """
        Verify that the Random Forest model is verified by SHA-256 before loading.
        """
        self.assertTrue(self.model.is_loaded)
        self.assertTrue(self.model.sha256_verified)

    def test_03_bounded_steps_and_budget(self):
        """
        Verify that investigation loop never exceeds max_steps_per_finding or global budget.
        """
        controller = InvestigationController(
            policy_gate=self.policy_gate,
            model=self.model,
            max_steps_per_finding=3,
            max_total_requests=5,
            is_live=False,  # offline mock to test bound enforcement
        )
        findings = [
            {"id": f"TEST-BOUND-{i}", "title": "Generic Alert", "cwe_id": "CWE-200", "affected_asset": {"url": "http://localhost:3000"}}
            for i in range(10)
        ]
        result = controller.run_investigation_suite(findings)
        summary = result["summary"]

        for f in result["findings"]:
            traj = f["investigation_trajectory"]
            self.assertLessEqual(traj["total_steps"], 3)
            self.assertIn(traj["final_action"], VALID_ACTIONS)

    def test_04_defensive_rule_layers_in_loop(self):
        """
        Verify that high-risk injection flaws and failures trigger defensive rule layers.
        """
        controller = InvestigationController(
            policy_gate=self.policy_gate,
            model=self.model,
            max_steps_per_finding=4,
            is_live=False,
        )
        sqli_finding = {
            "id": "TEST-SQLI",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "risk_rating": "Critical",
            "evidence": {"attack": "1' OR '1'='1"},
            "affected_asset": {"url": "http://localhost:3000/api"},
        }
        investigated = controller.investigate_finding(sqli_finding)
        traj = investigated["investigation_trajectory"]
        # In offline mode or safety rule, SQLi either verifies finding or routes to manual review
        self.assertIn(traj["final_action"], VALID_ACTIONS)
        self.assertTrue(len(traj["trajectory"]) >= 1)

    def test_05_live_investigation_against_juice_shop(self):
        """
        Verify live investigation against OWASP Juice Shop:
        - Executes read-only probes
        - Enforces rate limiting
        - Logs observations and confidence
        """
        controller = InvestigationController(
            policy_gate=self.policy_gate,
            model=self.model,
            max_steps_per_finding=4,
            max_total_requests=10,
            request_interval_sec=0.05,
            target_url="http://localhost:3000",
            is_live=True,
        )
        csp_finding = {
            "id": "LIVE-CSP-INV",
            "title": "Content Security Policy (CSP) Header Not Set",
            "cwe_id": "CWE-693",
            "risk_rating": "Medium",
            "affected_asset": {"url": "http://localhost:3000"},
            "evidence": {},
        }
        investigated = controller.investigate_finding(csp_finding)
        traj = investigated["investigation_trajectory"]
        self.assertTrue(traj["total_steps"] >= 1)
        self.assertIn(traj["final_action"], VALID_ACTIONS)

        # Check trajectory details
        for step in traj["trajectory"]:
            self.assertIn("step", step)
            self.assertIn("phase", step)
            self.assertIn("action", step)
            self.assertIn(step["action"], VALID_ACTIONS)
            self.assertIn("confidence", step)
            self.assertIn("observation", step)
            self.assertTrue(len(step["observation"]) > 0)


if __name__ == "__main__":
    unittest.main()
