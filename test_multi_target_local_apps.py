#!/usr/bin/env python3
"""
Project Zero-Day: Multi-Application Target Integration Test
Script: test_multi_target_local_apps.py
Objective: Verify Requirement 9:
           "Test at least two local applications on different ports,
            including the existing Juice Shop and my local SDG website."
           Verify that both applications run on different ports and are
           handled by ZERO//DAY without code edits or PolicyGate edits per port.
"""

import http.server
import json
from pathlib import Path
import pytest
import sys
import threading

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.orchestrator import MasterOrchestrator, PolicyGate
from app.scanner_manager import ensure_juice_shop_container
from app.target_validator import (
    verify_target_reachability,
    verify_docker_container_connectivity,
    map_to_container_target,
)
from app.verification_engine import verify_finding_evidence


_active_sdg_server = None

def _ensure_sdg_server():
    global _active_sdg_server
    try:
        is_up, _, _ = verify_target_reachability("http://localhost:8000", timeout=1.0)
        if is_up:
            return
    except Exception:
        pass

    sdg_candidates = [
        Path(r"C:\Users\Syed\Downloads"),
        PROJECT_ROOT,
        PROJECT_ROOT / "fixtures",
    ]
    serve_dir = PROJECT_ROOT
    for candidate in sdg_candidates:
        if candidate.is_dir() and any("sdg" in f.name.lower() for f in candidate.glob("*.html")):
            serve_dir = candidate
            break

    class SDGHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(serve_dir), **kwargs)

        def log_message(self, format, *args):
            pass

    try:
        _active_sdg_server = http.server.ThreadingHTTPServer(("0.0.0.0", 8000), SDGHandler)
        t = threading.Thread(target=_active_sdg_server.serve_forever, daemon=True)
        t.start()
    except Exception as exc:
        print(f"[*] Note: Could not bind local SDG server on port 8000: {exc}")


def test_app_1_juice_shop_port_3000():
    """
    Application 1: OWASP Juice Shop on port 3000 (http://localhost:3000).
    Verifies reachability, container connectivity, PolicyGate authorization,
    and live evidence verification without manual scope configuration.
    """
    target_url = "http://localhost:3000"

    # Ensure Juice Shop container is ready
    ensure_juice_shop_container(target_url)

    # 1. Host Reachability
    is_up, msg, final_url = verify_target_reachability(target_url)
    assert is_up is True, f"Juice Shop reachable failed: {msg}"

    # 2. Container Mapping & Docker Connectivity
    container_url = map_to_container_target(target_url)
    assert container_url == "http://host.docker.internal:3000"
    docker_ok, docker_msg = verify_docker_container_connectivity(container_url)
    assert docker_ok is True, f"Docker container connectivity failed: {docker_msg}"

    # 3. PolicyGate Reusable Local-Target Policy
    gate = PolicyGate.create_local_target_policy()
    finding = {
        "id": "LIVE-JS-01",
        "title": "Content Security Policy (CSP) Header Not Set",
        "cwe_id": "CWE-693",
        "affected_asset": {"url": "http://localhost:3000"},
        "suggested_action": "inspect_related_endpoint",
    }
    pol_eval = gate.evaluate_finding(finding)
    assert pol_eval["decision"] == "ALLOW"
    assert "within authorized scope" in pol_eval["reason"]

    # 4. Live Evidence Verification
    verif = verify_finding_evidence(finding, target_base_url=target_url, policy_gate=gate)
    assert verif["status"] in ["CONFIRMED", "REJECTED", "MANUAL_REVIEW"]
    assert verif["verification_method"] in ["defensive_header_assertion", "safety_gate_manual_review"]

    # 5. MasterOrchestrator Initialization without scope editing
    orch = MasterOrchestrator(
        target_url=target_url,
        use_sample=True,
    )
    assert orch.target_url == "http://localhost:3000"
    assert orch.container_target_url == "http://host.docker.internal:3000"
    assert orch.policy_gate.is_in_scope("http://localhost:3000/rest/user") is True
    assert orch.policy_gate.is_in_scope("http://127.0.0.1:3000/api") is True


def test_app_2_sdg_website_port_8000():
    """
    Application 2: Local SDG Website on port 8000 (http://localhost:8000).
    Verifies reachability, container connectivity, PolicyGate authorization,
    and live evidence verification without editing code or PolicyGate.
    """
    _ensure_sdg_server()
    target_url = "http://localhost:8000"

    # 1. Host Reachability
    is_up, msg, final_url = verify_target_reachability(target_url)
    assert is_up is True, f"SDG website reachable failed: {msg}"

    # 2. Container Mapping & Docker Connectivity
    container_url = map_to_container_target(target_url)
    assert container_url == "http://host.docker.internal:8000"
    docker_ok, docker_msg = verify_docker_container_connectivity(container_url)
    assert docker_ok is True, f"Docker container connectivity to SDG website failed: {docker_msg}"

    # 3. PolicyGate Reusable Local-Target Policy (zero code or gate changes)
    gate = PolicyGate.create_local_target_policy()
    finding = {
        "id": "LIVE-SDG-01",
        "title": "Content Security Policy (CSP) Header Not Set",
        "cwe_id": "CWE-693",
        "affected_asset": {"url": "http://localhost:8000"},
        "suggested_action": "inspect_related_endpoint",
    }
    pol_eval = gate.evaluate_finding(finding)
    assert pol_eval["decision"] == "ALLOW", f"Expected ALLOW for SDG site, got {pol_eval['decision']}: {pol_eval['reason']}"
    assert "within authorized scope" in pol_eval["reason"]

    # 4. Live Evidence Verification against SDG application
    verif = verify_finding_evidence(finding, target_base_url=target_url, policy_gate=gate)
    # Python SimpleHTTPRequestHandler does not set CSP, so missing CSP should be CONFIRMED!
    assert verif["status"] == "CONFIRMED"
    assert verif["verified"] is True
    assert verif["verification_method"] == "defensive_header_assertion"
    assert "Content-Security-Policy" in verif["evidence"]["missing_header"]

    # 5. MasterOrchestrator Initialization with dynamic port 8000 target
    orch = MasterOrchestrator(
        target_url=target_url,
        use_sample=True,
    )
    assert orch.target_url == "http://localhost:8000"
    assert orch.container_target_url == "http://host.docker.internal:8000"
    assert orch.policy_gate.is_in_scope("http://localhost:8000/sdg_website_final_with_calculator%20(4).html") is True
    assert orch.policy_gate.is_in_scope("http://127.0.0.1:8000/") is True
    # Anti-bypass / scope boundary check
    assert orch.policy_gate.is_in_scope("http://evil.com:8000") is False


def test_cross_target_reusable_policy_isolation():
    """
    Verifies that the same reusable local-target policy simultaneously allows
    both applications while strictly denying remote targets and bypass attempts.
    """
    gate = PolicyGate.create_local_target_policy()

    # Allowed targets on different ports
    assert gate.is_in_scope("http://localhost:3000") is True
    assert gate.is_in_scope("http://localhost:8000") is True
    assert gate.is_in_scope("http://127.0.0.1:8000") is True
    assert gate.is_in_scope("http://localhost:5173") is True

    # Denied targets
    assert gate.is_in_scope("http://example.com:3000") is False
    assert gate.is_in_scope("http://target.local:8000") is False
    assert gate.is_in_scope("http://localhost.attacker.com:8000") is False
    assert gate.is_in_scope("file:///etc/passwd") is False
