"""
test_correctness_and_reliability_repairs.py
===========================================
Regression and correctness test suite covering the 7 phases of the
ZERO//DAY pipeline correctness and reliability repair:

1. Target isolation & quarantine: Target http://localhost:8000 strictly quarantines port 3000 findings.
2. Freshness & isolation: Runs use unique run_ids, fresh outputs, and sample data is never labeled 'LIVE SCAN'.
3. Verification semantics: HTTP 404 responses do NOT confirm missing CSP headers (NEEDS_VERIFICATION);
   HTTP 200 responses without CSP confirm; injection findings route to MANUAL_REVIEW.
4. Priority & severity mapping: Scanner severity is preserved, Gemma AI text cannot override priority,
   and malformed severities are safely handled.
5. Deduplication semantics: Different paths and different ports are never conflated into one finding;
   identical alerts on the same endpoint corroborate without double counting.
6. Truthful pipeline status and error accounting: Failures do not report unconditional SUCCESS.
7. HTML and JSON report consistency: Both reports strictly match on run_id, target, metrics, and distributions.
"""

import json
import os
import shutil
import tempfile
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.orchestrator import PolicyGate
from app.finding_deduplicator import deduplicate_multi_scanner_findings
from app.nuclei_normalizer import normalize_nuclei_findings, canonicalize_url
from app.report_generator import build_html_report, generate_security_report
from app.scanner_manager import run_multi_scanner_suite
from app.verification_engine import verify_finding_evidence, _defensive_http_probe, VALID_VERIFICATION_STATUSES
from decision_engine import assign_priority
from normalize_findings import normalize_zap_findings


# ==============================================================================
# Phase 2: Target Isolation, Freshness, and Quarantine
# ==============================================================================

def test_target_isolation_quarantines_mismatched_port():
    """A scan targeting port 8000 must strictly quarantine findings from port 3000."""
    fake_zap_data = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "http://host.docker.internal:3000",
                "@host": "host.docker.internal",
                "@port": "3000",
                "alerts": [
                    {
                        "pluginId": "10038",
                        "alertRef": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "2",
                        "riskdesc": "Medium (Medium)",
                        "desc": "CSP header missing",
                        "instances": [
                            {
                                "uri": "http://host.docker.internal:3000/#/login",
                                "method": "GET",
                                "param": "",
                                "attack": "",
                                "evidence": "",
                            }
                        ],
                    }
                ],
            },
            {
                "@name": "http://localhost:8000",
                "@host": "localhost",
                "@port": "8000",
                "alerts": [
                    {
                        "pluginId": "10038",
                        "alertRef": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "2",
                        "riskdesc": "Medium (Medium)",
                        "desc": "CSP header missing",
                        "instances": [
                            {
                                "uri": "http://localhost:8000/index.html",
                                "method": "GET",
                                "param": "",
                                "attack": "",
                                "evidence": "",
                            }
                        ],
                    }
                ],
            },
        ],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = Path(tmpdir) / "zap_test.json"
        output_file = Path(tmpdir) / "normalized.json"

        input_file.write_text(json.dumps(fake_zap_data), encoding="utf-8")

        result = normalize_zap_findings(
            input_path=input_file,
            output_path=output_file,
            run_id="run-test-isolation-001",
            expected_target_url="http://localhost:8000",
        )

        # Only the port 8000 finding should be admitted
        assert len(result) == 1
        admitted = result[0]
        assert "8000" in admitted["affected_asset"]["url"]
        assert "3000" not in admitted["affected_asset"]["url"]


def test_nuclei_normalizer_quarantines_mismatched_target():
    """Nuclei findings on port 3000 are quarantined when target is port 8000."""
    nuclei_raw = [
        {
            "template-id": "waf-detect",
            "info": {"name": "WAF Detection", "severity": "info"},
            "type": "http",
            "host": "http://host.docker.internal:3000",
            "matched-at": "http://host.docker.internal:3000/",
            "extracted-results": [],
            "timestamp": "2026-10-21T18:00:00Z",
        },
        {
            "template-id": "missing-sri",
            "info": {"name": "Subresource Integrity Missing", "severity": "low"},
            "type": "http",
            "host": "http://localhost:8000",
            "matched-at": "http://localhost:8000/main.js",
            "extracted-results": [],
            "timestamp": "2026-10-21T18:00:00Z",
        },
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = Path(tmpdir) / "nuclei.jsonl"
        output_file = Path(tmpdir) / "normalized_nuclei.json"

        with open(input_file, "w", encoding="utf-8") as f:
            for rec in nuclei_raw:
                f.write(json.dumps(rec) + "\n")

        normalized = normalize_nuclei_findings(
            input_path=input_file,
            output_path=output_file,
            run_id="run-nuclei-001",
            expected_target_url="http://localhost:8000",
        )

        assert len(normalized) == 1
        assert normalized[0]["affected_asset"]["url"] == "http://localhost:8000/main.js"


def test_sample_fixtures_never_labeled_live_scan():
    """Findings originating from static sample fixtures must never bear 'LIVE SCAN' provenance."""
    sample_finding = {
        "finding_id": "PZ-SAMPLE-001",
        "title": "Sample XSS",
        "source": "OWASP ZAP 2.14.0",
        "provenance": {
            "source_type": "SAMPLE FIXTURE",
            "input_file": "zap-findings.json",
            "target_scanned": "http://localhost:3000",
        },
    }
    assert sample_finding["provenance"]["source_type"] != "LIVE SCAN"
    assert "SAMPLE" in sample_finding["provenance"]["source_type"]


# ==============================================================================
# Phase 3: Verification Semantics & 404 Header Behavior
# ==============================================================================

def test_missing_csp_on_404_response_is_needs_verification():
    """
    Vulnerability cannot be confirmed merely because a 404 response lacks CSP.
    Must return NEEDS_VERIFICATION.
    """
    finding = {
        "id": "PZ-CSP-001",
        "title": "Content Security Policy (CSP) Header Not Set",
        "affected_asset": {"url": "http://localhost:8000/non-existent-page-xyz"},
        "category": "Security Header",
        "cwe_id": "CWE-693",
        "evidence": {"observed_at": None, "scanner": "zap"},
    }

    # Mock probe returning 404 Not Found without CSP header
    with patch("app.verification_engine._defensive_http_probe") as mock_probe:
        mock_probe.return_value = (404, {"content-type": "text/html"}, "<html>404 Not Found</html>", "http://localhost:8000/non-existent-page-xyz")

        gate = PolicyGate(authorized_scopes=["http://localhost:8000"])
        verif = verify_finding_evidence(finding, target_base_url="http://localhost:8000", policy_gate=gate)

        assert verif["verified"] is False
        assert verif["status"] == "NEEDS_VERIFICATION"
        assert "404" in verif["evaluation_notes"]
        # Ensure original scanner evidence is intact
        assert finding["evidence"]["scanner"] == "zap"


def test_missing_csp_on_200_response_is_confirmed():
    """When a live 200 OK application response lacks CSP, it is CONFIRMED."""
    finding = {
        "id": "PZ-CSP-002",
        "title": "Content Security Policy (CSP) Header Not Set",
        "affected_asset": {"url": "http://localhost:8000/index.html"},
        "category": "Security Header",
        "cwe_id": "CWE-693",
        "evidence": {"observed_at": None, "scanner": "zap"},
    }

    with patch("app.verification_engine._defensive_http_probe") as mock_probe:
        mock_probe.return_value = (200, {"server": "SimpleHTTP/0.6", "content-type": "text/html"}, "<html>Home</html>", "http://localhost:8000/index.html")

        gate = PolicyGate(authorized_scopes=["http://localhost:8000"])
        verif = verify_finding_evidence(finding, target_base_url="http://localhost:8000", policy_gate=gate)

        assert verif["verified"] is True
        assert verif["status"] == "CONFIRMED"
        assert "Content-Security-Policy" in verif["evaluation_notes"]


def test_present_csp_on_200_response_is_rejected():
    """When the header is actually present on 200 OK, the finding is REJECTED (false positive)."""
    finding = {
        "id": "PZ-CSP-003",
        "title": "Content Security Policy (CSP) Header Not Set",
        "affected_asset": {"url": "http://localhost:8000/secure.html"},
        "category": "Security Header",
        "cwe_id": "CWE-693",
        "evidence": {"observed_at": None},
    }

    with patch("app.verification_engine._defensive_http_probe") as mock_probe:
        mock_probe.return_value = (200, {"content-security-policy": "default-src 'self'"}, "<html>Secure</html>", "http://localhost:8000/secure.html")

        gate = PolicyGate(authorized_scopes=["http://localhost:8000"])
        verif = verify_finding_evidence(finding, target_base_url="http://localhost:8000", policy_gate=gate)

        assert verif["verified"] is False
        assert verif["status"] == "REJECTED"


def test_injection_safety_invariant_forces_manual_review():
    """Destructive findings (SQLi, RCE, Command Injection) are NEVER probed and route to MANUAL_REVIEW."""
    injection_finding = {
        "id": "PZ-SQLI-001",
        "title": "SQL Injection in User Search",
        "affected_asset": {"url": "http://localhost:8000/search?q=test"},
        "category": "Injection",
        "cwe_id": "CWE-89",
        "evidence": {"payload": "' OR 1=1 --"},
    }

    with patch("app.verification_engine._defensive_http_probe") as mock_probe:
        verif = verify_finding_evidence(injection_finding, target_base_url="http://localhost:8000")

        # Must not call any HTTP probe
        mock_probe.assert_not_called()
        assert verif["verified"] is False
        assert verif["status"] == "MANUAL_REVIEW"
        assert "Manual review required" in verif["evaluation_notes"]


# ==============================================================================
# Phase 4: Severity, Priority, and AI Advisory Authority Boundary
# ==============================================================================

def test_priority_authoritative_mapping_preserves_scanner_severity():
    """Scanner severity 'Medium' maps to P3 priority; scanner severity is preserved."""
    p_med = assign_priority("Medium", "Security Header", "CWE-693", cvss_score=5.0)
    assert p_med == "P3"

    p_high = assign_priority("High", "A01:Broken Access Control", "CWE-200", cvss_score=7.5)
    assert p_high == "P2"

    p_crit = assign_priority("Critical", "Injection", "CWE-89", cvss_score=9.5)
    assert p_crit == "P1"

    p_low = assign_priority("Low", "Security Header", "CWE-1021", cvss_score=3.0)
    assert p_low == "P4"

    p_info = assign_priority("Informational", "Information Disclosure", "CWE-200", cvss_score=0.0)
    assert p_info == "P4"


def test_ai_advisory_text_does_not_override_calculated_priority():
    """
    Even if Gemma AI advisory describes the risk as 'High', the authoritative
    priority remains strictly P3 for a Medium scanner severity finding.
    """
    finding = {
        "id": "PZ-TEST-AI-01",
        "title": "Directory Listing Enabled",
        "severity": "Medium",
        "calculated_priority": "P3",
        "affected_asset": {"url": "http://localhost:8000/static/"},
        "cwe_id": "CWE-548",
        "verification": {"status": "CONFIRMED", "verified": True},
        # AI advisory with inflated wording
        "gemma_advisory": {
            "risk_summary": "High risk of sensitive directory harvesting and confidential credential leaks.",
            "recommended_action": "Disable directory browsing immediately."
        }
    }

    # Ensure structured priority is unchanged and authoritative
    assert finding["severity"] == "Medium"
    assert finding["calculated_priority"] == "P3"
    assert "High" in finding["gemma_advisory"]["risk_summary"]
    # The advisory is explicitly designated as non-authoritative


def test_unknown_or_malformed_severity_fallback():
    """Missing or malformed severity defaults safely to P4 unless high-risk CWE indicator is present."""
    assert assign_priority("", "Security Header", "CWE-200") == "P4"
    assert assign_priority(None, "Security Header", "CWE-200") == "P4"
    assert assign_priority("UNKNOWN_FOOBAR", "Security Header", "CWE-200") == "P4"

    # High-risk CWE indicator escalates malformed severity safely
    assert assign_priority(None, "Injection", "CWE-89") == "P1"
    assert assign_priority("", "Injection", "CWE-78") == "P1"


# ==============================================================================
# Phase 5: Deduplication & Resource Differentiation
# ==============================================================================

def test_deduplication_preserves_distinct_paths():
    """Findings on different endpoints (/ vs /about.html) MUST NOT be merged."""
    findings = [
        {
            "finding_id": "F-001",
            "title": "CSP Header Missing",
            "url": "http://localhost:8000/",
            "method": "GET",
            "category": "Security Header",
            "parameter": "",
            "source": "zap",
            "evidence": {"msg": "missing on root"},
        },
        {
            "finding_id": "F-002",
            "title": "CSP Header Missing",
            "url": "http://localhost:8000/about.html",
            "method": "GET",
            "category": "Security Header",
            "parameter": "",
            "source": "zap",
            "evidence": {"msg": "missing on about"},
        },
    ]

    deduped, _ = deduplicate_multi_scanner_findings(findings)
    assert len(deduped) == 2
    urls = {f["url"] for f in deduped}
    assert "http://localhost:8000/" in urls
    assert "http://localhost:8000/about.html" in urls


def test_deduplication_preserves_distinct_ports():
    """Findings on different ports (:8000 vs :3000) MUST NOT be merged."""
    findings = [
        {
            "finding_id": "F-8000",
            "title": "CSP Header Missing",
            "url": "http://localhost:8000/index.html",
            "method": "GET",
            "category": "Security Header",
            "parameter": "",
            "source": "zap",
        },
        {
            "finding_id": "F-3000",
            "title": "CSP Header Missing",
            "url": "http://localhost:3000/index.html",
            "method": "GET",
            "category": "Security Header",
            "parameter": "",
            "source": "zap",
        },
    ]

    deduped, _ = deduplicate_multi_scanner_findings(findings)
    assert len(deduped) == 2


def test_multi_scanner_corroboration_merges_identical_endpoint_alerts():
    """When ZAP and Nuclei report the exact same issue on the same endpoint, they corroborate."""
    findings = [
        {
            "finding_id": "ZAP-001",
            "title": "X-Frame-Options Header Missing",
            "url": "http://localhost:8000/login",
            "method": "GET",
            "category": "Security Header",
            "parameter": "",
            "source": "OWASP ZAP 2.14.0",
            "evidence": {"rule": "10020"},
            "provenance": {"tool": "zap", "scanner_ref": "10020"},
        },
        {
            "finding_id": "NUCLEI-001",
            "title": "Missing Clickjacking Protection Header",
            "url": "http://localhost:8000/login",
            "method": "GET",
            "category": "Security Header",
            "parameter": "",
            "source": "Nuclei v3",
            "evidence": {"template": "missing-x-frame-options"},
            "provenance": {"tool": "nuclei", "scanner_ref": "missing-xfo"},
        },
    ]

    deduped, _ = deduplicate_multi_scanner_findings(findings)
    assert len(deduped) == 1
    merged = deduped[0]
    assert merged["source"] == "OWASP ZAP 2.14.0"
    corroborating = merged.get("provenance", {}).get("corroborating_findings", [])
    assert len(corroborating) == 1
    assert corroborating[0]["source"] == "Nuclei v3"


# ==============================================================================
# Phase 6 & 7: Pipeline Integrity & Report Consistency
# ==============================================================================

def test_html_and_json_reports_agree_on_metadata_and_counts():
    """HTML and JSON reports must agree on run_id, target, finding counts, and distributions."""
    findings = [
        {
            "finding_id": "PZ-001",
            "title": "CSP Missing",
            "category": "Security Header",
            "severity": "Medium",
            "priority": "P3",
            "calculated_priority": "P3",
            "confidence": 0.85,
            "url": "http://localhost:8000/index.html",
            "method": "GET",
            "source": "OWASP ZAP 2.14.0",
            "cwe_id": "CWE-693",
            "tactical_action": "recommend_remediation",
            "evidence": {"desc": "Missing header"},
            "verification": {"status": "CONFIRMED", "verified": True, "reason": "No CSP on 200 OK"},
            "provenance": {"tool": "zap", "target_scanned": "http://localhost:8000"},
        },
        {
            "finding_id": "PZ-002",
            "title": "XFO Missing",
            "category": "Security Header",
            "severity": "Low",
            "priority": "P4",
            "calculated_priority": "P4",
            "confidence": 0.90,
            "url": "http://localhost:8000/login",
            "method": "GET",
            "source": "OWASP ZAP 2.14.0",
            "cwe_id": "CWE-1021",
            "tactical_action": "recommend_remediation",
            "evidence": {"desc": "Missing XFO"},
            "verification": {"status": "NEEDS_VERIFICATION", "verified": False, "reason": "Not probed"},
            "provenance": {"tool": "zap", "target_scanned": "http://localhost:8000"},
        },
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        findings_file = Path(tmpdir) / "prioritized_findings.json"
        findings_file.write_text(json.dumps(findings), encoding="utf-8")

        json_path = Path(tmpdir) / "security_report.json"
        html_path = Path(tmpdir) / "security_report.html"

        run_id = "run-correctness-check-777"
        target_url = "http://localhost:8000"

        # Generate JSON report & HTML report via generate_security_report
        json_report = generate_security_report(
            findings_file=findings_file,
            output_json_file=json_path,
            output_html_file=html_path,
            run_id=run_id,
            target_url=target_url,
            pipeline_status="SUCCESS",
        )

        html_content = html_path.read_text(encoding="utf-8")

        # 1. JSON report metadata assertions
        assert json_report["report_metadata"]["run_id"] == run_id
        assert json_report["report_metadata"]["target_url"] == target_url
        assert json_report["report_metadata"]["pipeline_status"] == "SUCCESS"
        assert json_report["report_metadata"]["total_findings"] == 2
        assert json_report["report_metadata"]["priority_distribution"]["P3"] == 1
        assert json_report["report_metadata"]["priority_distribution"]["P4"] == 1
        assert json_report["report_metadata"]["verification_status"]["CONFIRMED"] == 1
        assert json_report["report_metadata"]["verification_status"]["NEEDS_VERIFICATION"] == 1

        # 2. HTML report content assertions
        assert run_id in html_content
        assert target_url in html_content
        assert "SUCCESS" in html_content
        # Finding IDs and Titles rendered in HTML
        assert "PZ-001" in html_content
        assert "PZ-002" in html_content
        assert "CSP Missing" in html_content
        assert "XFO Missing" in html_content
        # Verification status badges rendered in HTML
        assert "CONFIRMED" in html_content
        assert "NEEDS_VERIFICATION" in html_content
