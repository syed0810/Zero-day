#!/usr/bin/env python3
"""
Project Zero-Day - Stage 2: Ollama & Gemma Advisory Service Integration Tests
Script: test_gemma_integration.py
Objective: Verify all Stage 2 testing requirements:
           1. Ollama connection health check
           2. Structured inference with sample CVE/CWE finding payload
           3. Fallback behavior when Ollama service is stopped
           4. Markdown-wrapped JSON parsing resilience
           5. Immutability of verification status (Hard Constraint)
"""

import json
import sys
import time
import unittest
from pathlib import Path

# Add project root and app directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from app.gemma_advisory import GemmaAdvisoryClient
 
 
class TestGemmaAdvisoryIntegration(unittest.TestCase):
    """
    Test suite covering local Ollama integration and fallback behaviors.
    """

    @classmethod
    def setUpClass(cls):
        import os
        timeout = float(os.environ.get("OLLAMA_TIMEOUT", "90.0"))
        cls.client = GemmaAdvisoryClient(base_url="http://127.0.0.1:11434", timeout=timeout)

    def test_01_ollama_connection_health_check(self):
        """
        Testing Requirement 1: Test Ollama connection health check.
        """
        is_healthy, status_msg = self.client.check_health()
        self.assertTrue(is_healthy, f"Expected Ollama to be healthy, got: {status_msg}")
        self.assertIn("11434", status_msg)

        models = self.client.list_available_models()
        self.assertIsInstance(models, list)
        self.assertTrue(any("gemma" in m.lower() for m in models), f"No Gemma model found in {models}")
        print(f"\n[PASS] Test 1: Health check passed. Models available: {models}")

    def test_02_structured_inference_sample_finding(self):
        """
        Testing Requirement 2: Test structured inference with a sample CVE/CWE finding payload.
        Verifies gemma_explanation, remediation_advice, risk_summary, and telemetry.
        """
        sample_finding = {
            "id": "TEST-CWE-89-001",
            "source_type": "web",
            "source_tool": "OWASP ZAP",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "risk_rating": "High",
            "priority": "P1",
            "affected_asset": {
                "url": "http://target.local/api/items?id=1",
                "method": "GET",
                "parameter": "id",
            },
            "description": "SQL injection may be possible in id parameter.",
            "evidence": {
                "observed_at": None,
                "attack": "1' OR '1'='1",
                "evidence": "syntax error near OR",
            },
            "verification": {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
            },
            "ai_advisory": {
                "recommendation": "Use parameterized queries",
                "reference": "https://cwe.mitre.org/data/definitions/89.html",
            },
        }

        enriched, telemetry = self.client.enrich_finding(sample_finding)

        self.assertIsNotNone(telemetry, "Expected telemetry metadata from inference call")
        self.assertGreater(telemetry["latency_ms"], 0.0)
        self.assertGreater(telemetry["prompt_eval_count"], 0)
        self.assertGreater(telemetry["eval_count"], 0)

        advisory = enriched.get("ai_advisory", {})
        # FR-02: Structured keys present
        self.assertIn("gemma_explanation", advisory)
        self.assertIn("remediation_advice", advisory)
        self.assertIn("risk_summary", advisory)
        self.assertTrue(len(advisory["gemma_explanation"]) > 20)
        self.assertTrue(len(advisory["remediation_advice"]) > 20)
        self.assertTrue(len(advisory["risk_summary"]) > 10)

        # FR-04: is_ai_generated must be true
        self.assertTrue(advisory.get("is_ai_generated") is True)
        self.assertIn("untrusted", advisory.get("disclaimer", "").lower())

        # Hard Constraint: verification status MUST NOT be modified
        self.assertFalse(enriched["verification"]["verified"])
        self.assertEqual(enriched["verification"]["status"], "NEEDS_VERIFICATION")

        print(f"[PASS] Test 2: Structured inference successful ({telemetry['latency_ms']:.1f}ms).")
        print(f"       Prompt tokens: {telemetry['prompt_eval_count']}, Generated tokens: {telemetry['eval_count']}")

    def test_03_fallback_behavior_service_stopped(self):
        """
        Testing Requirement 3: Verify fallback behavior when Ollama service is stopped.
        """
        # Create client pointed to an offline port
        offline_client = GemmaAdvisoryClient(base_url="http://127.0.0.1:59999", timeout=1.0)

        # Confirm health check reports offline
        is_healthy, status_msg = offline_client.check_health()
        self.assertFalse(is_healthy)
        self.assertIn("unreachable", status_msg.lower())

        # Test inference with fallback
        sample_finding = {
            "id": "TEST-CWE-79-002",
            "source_type": "web",
            "source_tool": "OWASP ZAP",
            "title": "Cross Site Scripting (Reflected)",
            "cwe_id": "CWE-79",
            "risk_rating": "High",
            "affected_asset": {"url": "http://target.local/search?q=test"},
            "description": "Reflected XSS in search parameter",
            "verification": {"status": "NEEDS_VERIFICATION", "verified": False},
            "ai_advisory": {},
        }

        # Must execute without raising unhandled connection exception
        enriched, telemetry = offline_client.enrich_finding(sample_finding)

        self.assertIsNone(telemetry)
        advisory = enriched["ai_advisory"]
        self.assertTrue(advisory.get("is_fallback") is True)
        self.assertFalse(advisory.get("is_ai_generated"))
        self.assertIn("gemma_explanation", advisory)
        self.assertIn("remediation_advice", advisory)
        self.assertIn("risk_summary", advisory)
        self.assertIn("fallback_reason", advisory)

        # Hard Constraint: verification remains untouched
        self.assertFalse(enriched["verification"]["verified"])
        self.assertEqual(enriched["verification"]["status"], "NEEDS_VERIFICATION")

        print(f"[PASS] Test 3: Fallback handling verified without exception. Reason: {advisory['fallback_reason'][:50]}...")

    def test_04_markdown_wrapped_json_parsing(self):
        """
        Hard Constraint: Handle JSON parsing errors gracefully when LLM output
        contains extra markdown text or conversational preambles.
        """
        raw_markdown_output = """Here is the vulnerability analysis in JSON format:
```json
{
  "gemma_explanation": "Markdown wrapped explanation.",
  "remediation_advice": "Apply secure encoding.",
  "risk_summary": "High risk."
}
```
Hope this helps defensive engineering!"""

        extracted = self.client._extract_json(raw_markdown_output)
        self.assertEqual(extracted["gemma_explanation"], "Markdown wrapped explanation.")
        self.assertEqual(extracted["remediation_advice"], "Apply secure encoding.")
        self.assertEqual(extracted["risk_summary"], "High risk.")
        print("[PASS] Test 4: Markdown wrapped JSON parsing handled successfully.")

    def test_05_verification_bypass_prevention(self):
        """
        Hard Constraint: Never allow Gemma model outputs to modify verification
        status or bypass policy controls.
        """
        corrupted_finding = {
            "id": "BYPASS-ATTEMPT",
            "title": "Bypass Test",
            "verification": {"status": "NEEDS_VERIFICATION", "verified": False},
            "ai_advisory": {},
        }

        # Even if an adversarial prompt or internal error attempts to flip verified: True
        enriched, _ = self.client.enrich_finding(corrupted_finding)
        self.assertFalse(enriched["verification"]["verified"])
        self.assertEqual(enriched["verification"]["status"], "NEEDS_VERIFICATION")
        print("[PASS] Test 5: Policy control invariant strictly enforced (verified: false).")


def run_tests() -> bool:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestGemmaAdvisoryIntegration)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
