#!/usr/bin/env python3
"""
Project Zero-Day - Stage 3: Scenario Dataset RAG Integration Tests
Script: test_rag_integration.py
Objective: Verify all Stage 3 testing requirements:
           1. SQLite FTS5 database record count and table integrity (~36.4K records)
           2. Search query performance and latency SLA (< 50ms)
           3. Zero-result handling for unknown CWEs
           4. Prompt context injection of retrieved scenario writeups
           5. RAG context enhancement in Gemma advisory outputs
           6. Strict preservation of verification status (Hard Constraint)
"""

import json
import sqlite3
import sys
import time
import unittest
from pathlib import Path

# Add project root and app directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "app"))

from pz_scenarios import get_db_path, get_relevant_scenarios, build_scenarios_db
from app.gemma_advisory import GemmaAdvisoryClient


class TestScenarioRAGIntegration(unittest.TestCase):
    """
    Test suite verifying SQLite FTS5 search index and RAG integration with Gemma.
    """

    @classmethod
    def setUpClass(cls):
        cls.db_path = get_db_path()
        if not cls.db_path.is_file():
            build_scenarios_db(db_path=cls.db_path)
        cls.client = GemmaAdvisoryClient()

    def test_01_sqlite_fts5_record_counts(self):
        """
        Definition of Done: SQLite FTS5 index contains ingested scenario records (~36K).
        """
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        scenarios_count = cur.execute("SELECT count(*) FROM scenarios").fetchone()[0]
        fts_count = cur.execute("SELECT count(*) FROM scenarios_fts").fetchone()[0]
        con.close()

        self.assertGreaterEqual(scenarios_count, 35000, f"Expected ~36K records, got {scenarios_count}")
        self.assertEqual(scenarios_count, fts_count, "Relational table count must match FTS5 table count")
        print(f"\n[PASS] Test 1: Ingested record count: {scenarios_count} (FTS5 overlay: {fts_count})")

    def test_02_fts5_search_performance_and_sla(self):
        """
        Testing Requirement: Test FTS5 search performance on CWE-693 and 'Content Security Policy'.
        Hard Constraint: Database queries must execute locally in < 50ms.
        """
        start = time.perf_counter()
        results = get_relevant_scenarios(cwe_id="CWE-693", vulnerability_class="Content Security Policy", limit=3)
        latency_ms = (time.perf_counter() - start) * 1000.0

        self.assertTrue(len(results) > 0, "Expected search results for Content Security Policy / CWE-693")
        self.assertLess(latency_ms, 50.0, f"Search latency ({latency_ms:.2f}ms) exceeded 50ms SLA")

        for r in results:
            self.assertIn("id", r)
            self.assertIn("title", r)
            self.assertIn("reference_context", r)
            self.assertTrue(r.get("is_advisory_context_only") is True)

        print(f"[PASS] Test 2: CWE-693 / CSP search returned {len(results)} matches in {latency_ms:.2f}ms (<50ms SLA).")

    def test_03_zero_result_unknown_cwe(self):
        """
        Testing Requirement: Test zero-result handling for unknown CWEs.
        """
        start = time.perf_counter()
        results = get_relevant_scenarios(cwe_id="CWE-99999", vulnerability_class="NONEXISTENT_SECURITY_TERM_98765", limit=3)
        latency_ms = (time.perf_counter() - start) * 1000.0

        self.assertEqual(len(results), 0, "Unknown CWE with bogus keyword must return 0 results")
        self.assertLess(latency_ms, 50.0)
        print(f"[PASS] Test 3: Zero-result query handled cleanly in {latency_ms:.2f}ms (returned {len(results)} items).")

    def test_04_rag_prompt_context_injection(self):
        """
        Functional Requirement FR-04: Ensure retrieved scenarios are explicitly passed
        to Gemma as reference context only.
        """
        sample_scenarios = [
            {
                "id": "SCEN-TEST-01",
                "title": "SQL Injection in User Login Handler",
                "cwe_id": "CWE-89",
                "summary": "Untrusted parameter concatenation into database query.",
            }
        ]

        prompt = self.client._build_prompt(
            title="SQL Injection",
            cwe_id="CWE-89",
            url="http://target.local/api/items?id=1",
            description="Dynamic SQL interpolation",
            method="GET",
            rag_scenarios=sample_scenarios,
        )

        self.assertIn("Reference Context (Advisory Only - Not Target Proof):", prompt)
        self.assertIn("SCEN-TEST-01", prompt)
        self.assertIn("SQL Injection in User Login Handler", prompt)
        print("[PASS] Test 4: RAG reference writeup dynamically injected into Gemma prompt.")

    def test_05_rag_enhancement_in_gemma_advisory_output(self):
        """
        Integration Test: Proving RAG context enhancement in Gemma outputs.
        Hard Constraint: Under no circumstances may AI or RAG alter verification status.
        """
        test_finding = {
            "id": "ZAP-40018-fe1cd503",
            "source_type": "web",
            "source_tool": "OWASP ZAP",
            "title": "SQL Injection",
            "cwe_id": "CWE-89",
            "risk_rating": "High",
            "affected_asset": {"url": "http://target.local/api/items?id=1", "method": "GET", "parameter": "id"},
            "description": "SQL injection may be possible in database query parameter.",
            "verification": {"status": "NEEDS_VERIFICATION", "verified": False},
            "ai_advisory": {},
        }

        enriched, telemetry = self.client.enrich_finding(test_finding)
        advisory = enriched.get("ai_advisory", {})

        # Verify RAG references populated
        self.assertTrue(advisory.get("rag_context_injected") is True, "rag_context_injected must be True")
        self.assertIsInstance(advisory.get("rag_references"), list)
        self.assertGreater(len(advisory["rag_references"]), 0, "rag_references list must contain items")

        # Verify Hard Constraint: verification status MUST remain untouched
        self.assertFalse(enriched["verification"]["verified"])
        self.assertEqual(enriched["verification"]["status"], "NEEDS_VERIFICATION")

        print(f"[PASS] Test 5: RAG enhancement verified in advisory output ({len(advisory['rag_references'])} references attached).")
        print(f"       Policy control preserved: verified={enriched['verification']['verified']}")


def run_tests() -> bool:
    suite = unittest.TestLoader().loadTestsFromTestCase(TestScenarioRAGIntegration)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
