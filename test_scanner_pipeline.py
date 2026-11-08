#!/usr/bin/env python3
"""
Project Zero-Day: Automated Multi-Scanner Pipeline Test Suite
Script: test_scanner_pipeline.py
Objective: Verify PolicyGate scope boundaries, anti-bypass protections,
           multi-scanner normalization, deduplication, and verification invariants.
"""

import json
from pathlib import Path
import pytest
import sys

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.orchestrator import PolicyGate, MasterOrchestrator
from app.nuclei_normalizer import normalize_nuclei_record, canonicalize_url, map_nuclei_severity
from app.finding_deduplicator import deduplicate_multi_scanner_findings, compute_correlation_key
from app.scanner_manager import check_docker_daemon, check_target_http, ensure_juice_shop_container


# ==============================================================================
# 1. PolicyGate Scope & Anti-Bypass Tests (Phase 4)
# ==============================================================================

def test_policy_gate_allows_valid_loopback_aliases():
    """PolicyGate must ALLOW all valid loopback aliases on port 3000."""
    gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    valid_urls = [
        "http://localhost:3000",
        "http://localhost:3000/rest/user/login",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3000/api/challenges",
        "http://host.docker.internal:3000",
        "http://host.docker.internal:3000/api-docs/swagger.json",
    ]

    for url in valid_urls:
        mock_finding = {
            "id": "TEST-01",
            "title": "Test Alert",
            "affected_asset": {"url": url},
            "suggested_action": "inspect_related_endpoint",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "ALLOW", f"Expected ALLOW for {url}, got {res['decision']}: {res['reason']}"
        assert "within authorized scope" in res["reason"]


def test_policy_gate_denies_wrong_ports():
    """PolicyGate must DENY targets on unauthorized ports to prevent port confusion."""
    gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    wrong_port_urls = [
        "http://localhost:8080/admin",
        "http://localhost:80/index.html",
        "http://localhost",  # Defaults to port 80
        "http://127.0.0.1:5000/api",
        "http://host.docker.internal:9090",
    ]

    for url in wrong_port_urls:
        mock_finding = {
            "id": "TEST-PORT",
            "title": "Port Confusion Test",
            "affected_asset": {"url": url},
            "suggested_action": "inspect_related_endpoint",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "DENY", f"Expected DENY for wrong port {url}, got {res['decision']}"
        assert "port" in res["reason"].lower()


def test_policy_gate_denies_unauthorized_hosts():
    """PolicyGate must DENY external or fixture mock hosts like target.local."""
    gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    unauth_hosts = [
        "http://target.local:3000/rest/user/login",
        "http://example.com:3000/",
        "http://internal.corp:3000/api",
    ]

    for url in unauth_hosts:
        mock_finding = {
            "id": "TEST-HOST",
            "title": "Unauthorized Host Test",
            "affected_asset": {"url": url},
            "suggested_action": "inspect_related_endpoint",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "DENY", f"Expected DENY for {url}, got {res['decision']}"
        assert "outside authorized scope" in res["reason"]


def test_policy_gate_anti_bypass_protections():
    """PolicyGate must reject subdomain suffix spoofing and userinfo confusion."""
    gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    bypass_attempts = [
        "http://localhost.evil.com:3000/exploit",
        "http://localhost-attacker.com:3000/",
        "http://localhost:3000@evil.com/login",
        "http://127.0.0.1.nip.io:3000/",
    ]

    for url in bypass_attempts:
        mock_finding = {
            "id": "TEST-BYPASS",
            "title": "Bypass Attempt",
            "affected_asset": {"url": url},
            "suggested_action": "inspect_related_endpoint",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "DENY", f"Expected DENY for bypass attempt {url}, got {res['decision']}"


def test_policy_gate_rejects_invalid_schemes_and_empty():
    """PolicyGate must reject non-HTTP schemes and empty/malformed URLs."""
    gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    invalid_urls = [
        "",
        None,
        "javascript:alert(1)",
        "file:///etc/passwd",
        "gopher://localhost:3000",
        "ftp://localhost:3000",
    ]

    for url in invalid_urls:
        mock_finding = {
            "id": "TEST-SCHEME",
            "title": "Invalid Scheme Test",
            "affected_asset": {"url": url},
            "suggested_action": "manual_review",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "DENY"


# ==============================================================================
# 2. Scanner Manager & Target Readiness Tests (Phase 2 & 6)
# ==============================================================================

def test_docker_daemon_responsive():
    """Docker CLI must be present and daemon responsive."""
    is_ok, msg = check_docker_daemon()
    assert is_ok is True, f"Docker daemon check failed: {msg}"


def test_juice_shop_reachable():
    """Juice Shop target must be responding on localhost:3000."""
    ensure_juice_shop_container("http://localhost:3000")
    is_up, msg = check_target_http("http://localhost:3000")
    assert is_up is True, f"Juice Shop reachable check failed: {msg}"


# ==============================================================================
# 3. Nuclei Normalizer & Canonicalization Tests (Phase 3 & 6)
# ==============================================================================

def test_nuclei_url_canonicalization():
    """Container target URLs must be canonicalized to localhost:3000."""
    raw = "http://host.docker.internal:3000/api-docs/swagger.json"
    canonical = canonicalize_url(raw)
    assert canonical == "http://localhost:3000/api-docs/swagger.json"

    raw_ip = "http://127.0.0.1:3000/rest/admin"
    assert canonicalize_url(raw_ip) == "http://localhost:3000/rest/admin"


def test_nuclei_record_normalization_structure():
    """Nuclei record normalization must produce standard schema with verified: false."""
    raw_record = {
        "template-id": "swagger-api",
        "info": {
            "name": "Public Swagger API - Detect",
            "severity": "info",
            "classification": {"cwe-id": ["cwe-200"]},
            "description": "Public Swagger API detected.",
        },
        "matched-at": "http://host.docker.internal:3000/api-docs/swagger.json",
        "curl-command": "curl http://host.docker.internal:3000/api-docs/swagger.json",
    }
    norm = normalize_nuclei_record(raw_record, 0, "nuclei-findings-live.jsonl")

    assert norm["source_tool"] == "ProjectDiscovery Nuclei"
    assert norm["cwe_id"] == "CWE-200"
    assert norm["risk_rating"] == "Informational"
    assert norm["affected_asset"]["url"] == "http://localhost:3000/api-docs/swagger.json"
    # Defensive invariant
    assert norm["verification"]["verified"] is False
    assert norm["verification"]["status"] == "NEEDS_VERIFICATION"


# ==============================================================================
# 4. Multi-Scanner Deduplication Tests (Phase 6)
# ==============================================================================

def test_multi_scanner_deduplication():
    """Overlapping findings on same endpoint and vulnerability class must be correlated."""
    finding_zap = {
        "id": "ZAP-10038-1",
        "source_tool": "OWASP ZAP",
        "title": "Content Security Policy (CSP) Header Not Set",
        "cwe_id": "CWE-693",
        "risk_rating": "Medium",
        "affected_asset": {"url": "http://localhost:3000", "parameter": ""},
        "evidence": {"attack": "GET / HTTP/1.1", "evidence": "Header missing"},
        "provenance": {"scanner": "OWASP ZAP"},
    }
    finding_nuclei = {
        "id": "NUC-csp-missing-1",
        "source_tool": "ProjectDiscovery Nuclei",
        "title": "CSP Header Missing",
        "cwe_id": "CWE-693",
        "risk_rating": "Low",
        "affected_asset": {"url": "http://localhost:3000", "parameter": ""},
        "evidence": {"attack": "curl http://localhost:3000"},
        "provenance": {"scanner": "ProjectDiscovery Nuclei"},
    }

    raw_list = [finding_zap, finding_nuclei]
    deduped, stats = deduplicate_multi_scanner_findings(raw_list)

    assert len(deduped) == 1, "Expected 2 overlapping findings to be deduplicated to 1"
    assert stats["raw_total"] == 2
    assert stats["deduplicated_total"] == 1
    assert stats["corroborated_count"] == 1
    assert deduped[0]["is_corroborated"] is True
    assert set(deduped[0]["scanners_detected"]) == {"OWASP ZAP", "ProjectDiscovery Nuclei"}
    assert len(deduped[0]["provenance"]["corroborating_findings"]) == 1


# ==============================================================================
# 5. Pipeline Defensive Invariants (All Stages)
# ==============================================================================

def test_defensive_verification_invariant():
    """Scanner findings must never be marked verified: true."""
    orchestrator = MasterOrchestrator(use_sample=True)
    findings = orchestrator.run_stage_1_normalization()
    for f in findings:
        assert f["verification"]["verified"] is False
        assert f["verification"]["status"] == "NEEDS_VERIFICATION"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
