#!/usr/bin/env python3
"""
Project Zero-Day: Target Input & Authorization Architecture Unit Test Suite
Script: test_target_input_and_authorization.py
Objective: Verify dynamic target input, URL format, scheme, host, port,
           reachability, redirect destination validation, Windows-host to
           Docker mapping, and reusable local-target authorization policy.
"""

import http.server
import json
from pathlib import Path
import pytest
import socket
import sys
import threading
import time
import urllib.parse

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.target_validator import (
    is_loopback_host,
    parse_and_validate_target,
    map_to_container_target,
    map_container_to_host_target,
    verify_target_reachability,
    verify_docker_container_connectivity,
    TargetValidationError,
    TargetUnreachableError,
    BlockedRedirectError,
    DockerConnectivityError,
)
from app.orchestrator import PolicyGate, MasterOrchestrator
from app.nuclei_normalizer import canonicalize_url


# ==============================================================================
# 1. URL Format, Scheme, Host, Port Validation Tests (Requirements 2, 3)
# ==============================================================================

def test_accept_valid_local_urls():
    """Accepts valid local URLs across various ports (3000, 8000, 5173)."""
    valid_cases = [
        ("http://localhost:3000", "http", "localhost", 3000),
        ("http://127.0.0.1:8000", "http", "127.0.0.1", 8000),
        ("http://localhost:5173", "http", "localhost", 5173),
        ("http://127.0.0.1:5173/dashboard", "http", "127.0.0.1", 5173),
        ("https://localhost:8443/app", "https", "localhost", 8443),
        ("http://127.0.0.2:9000", "http", "127.0.0.2", 9000),
        ("http://[::1]:8080", "http", "::1", 8080),
    ]

    for raw, exp_scheme, exp_host, exp_port in valid_cases:
        meta = parse_and_validate_target(raw, enforce_local=True)
        assert meta["scheme"] == exp_scheme
        assert meta["host"] == exp_host
        assert meta["port"] == exp_port
        assert meta["is_loopback"] is True


def test_reject_unsupported_schemes():
    """Rejects schemes other than HTTP and HTTPS with clear errors."""
    unsupported = [
        "ftp://localhost:8000",
        "file:///etc/passwd",
        "gopher://localhost:70",
        "javascript:alert(1)",
        "ws://localhost:3000",
    ]

    for raw in unsupported:
        with pytest.raises(TargetValidationError) as exc_info:
            parse_and_validate_target(raw)
        err = str(exc_info.value).lower()
        assert "unsupported scheme" in err or "only http and https" in err


def test_reject_invalid_ports():
    """Rejects out-of-range ports (< 1 or > 65535) with clear errors."""
    invalid_ports = [
        "http://localhost:0",
        "http://localhost:70000",
        "http://localhost:99999",
        "http://127.0.0.1:-1",
        "http://localhost:abc",
    ]

    for raw in invalid_ports:
        with pytest.raises(TargetValidationError) as exc_info:
            parse_and_validate_target(raw)
        assert "port" in str(exc_info.value).lower()


def test_reject_remote_and_spoofed_hosts():
    """Rejects non-loopback hosts and subdomain spoofing attempts."""
    blocked_hosts = [
        "http://example.com:8000",
        "http://target.local:3000",
        "http://internal.corp:8080",
        "http://localhost.evil.com:8000",
        "http://127.0.0.1.nip.io:8000",
        "http://localhost-attacker.com:3000",
        "http://localhost:3000@evil.com",
    ]

    for raw in blocked_hosts:
        with pytest.raises(TargetValidationError) as exc_info:
            parse_and_validate_target(raw, enforce_local=True)
        err = str(exc_info.value).lower()
        assert any(k in err for k in ["rejected", "only local", "prohibited", "userinfo"])


def test_reject_empty_or_malformed_urls():
    """Rejects empty, None, or schemeless/hostless strings."""
    malformed = ["", None, "http://", "://localhost:8000", "   "]

    for raw in malformed:
        with pytest.raises(TargetValidationError):
            parse_and_validate_target(raw)


# ==============================================================================
# 2. Windows-Host to Docker Container Address Mapping (Requirement 5)
# ==============================================================================

def test_map_to_container_target():
    """Maps Windows-host loopback addresses to host.docker.internal while preserving port."""
    mappings = [
        ("http://localhost:3000", "http://host.docker.internal:3000"),
        ("http://127.0.0.1:8000", "http://host.docker.internal:8000"),
        ("http://localhost:5173/app", "http://host.docker.internal:5173/app"),
        ("https://localhost:8443/login?q=1", "https://host.docker.internal:8443/login?q=1"),
        ("http://[::1]:9090", "http://host.docker.internal:9090"),
        ("http://host.docker.internal:3000", "http://host.docker.internal:3000"),
    ]

    for host_url, expected_container_url in mappings:
        result = map_to_container_target(host_url)
        assert result == expected_container_url


def test_canonicalize_container_to_host():
    """Canonicalizes container-internal URLs back to host localhost:<port>."""
    assert canonicalize_url("http://host.docker.internal:8000/api") == "http://localhost:8000/api"
    assert canonicalize_url("http://host.docker.internal:5173/feed") == "http://localhost:5173/feed"
    assert canonicalize_url("http://127.0.0.1:3000/rest") == "http://localhost:3000/rest"
    # Custom canonical host
    assert canonicalize_url("http://host.docker.internal:8000/api", canonical_host="127.0.0.1:8000") == "http://127.0.0.1:8000/api"


# ==============================================================================
# 3. Reachability & Redirect Safety Tests (Requirements 3, 7)
# ==============================================================================

class RedirectTestServer(http.server.BaseHTTPRequestHandler):
    """Test HTTP server implementing configurable redirects and routes."""

    def do_GET(self):
        if self.path == "/safe-redirect":
            self.send_response(302)
            self.send_header("Location", "/destination")
            self.end_headers()
        elif self.path == "/destination":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Safe local destination reached")
        elif self.path == "/evil-redirect":
            self.send_response(302)
            self.send_header("Location", "http://evil.com/phish")
            self.end_headers()
        elif self.path == "/unsupported-scheme-redirect":
            self.send_response(302)
            self.send_header("Location", "ftp://localhost:21/files")
            self.end_headers()
        elif self.path == "/loop-redirect-1":
            self.send_response(302)
            self.send_header("Location", "/loop-redirect-2")
            self.end_headers()
        elif self.path == "/loop-redirect-2":
            self.send_response(302)
            self.send_header("Location", "/loop-redirect-1")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

    def log_message(self, format, *args):
        # Silence HTTP server logs during test
        return


@pytest.fixture(scope="module")
def redirect_server():
    """Spins up a lightweight local HTTP server for redirect and reachability testing."""
    # Find free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = http.server.HTTPServer(("127.0.0.1", port), RedirectTestServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_reachability_success(redirect_server):
    """Verifies reachability probe succeeds against an active local server."""
    reachable, msg, final_url = verify_target_reachability(redirect_server)
    assert reachable is True
    assert "reachable" in msg.lower()


def test_reachability_unreachable_target():
    """Verifies clear TargetUnreachableError on connection failure."""
    dead_target = "http://127.0.0.1:59998"
    with pytest.raises(TargetUnreachableError) as exc_info:
        verify_target_reachability(dead_target, timeout=1.0)
    assert "unreachable" in str(exc_info.value).lower()


def test_safe_local_redirect_followed(redirect_server):
    """Verifies safe local redirect is followed to final destination."""
    url = f"{redirect_server}/safe-redirect"
    reachable, msg, final_url = verify_target_reachability(url)
    assert reachable is True
    assert "destination" in final_url


def test_blocked_external_redirect(redirect_server):
    """Verifies redirect attempting to route to external domain is blocked."""
    url = f"{redirect_server}/evil-redirect"
    with pytest.raises(BlockedRedirectError) as exc_info:
        verify_target_reachability(url)
    err = str(exc_info.value).lower()
    assert "blocked redirect" in err
    assert "evil.com" in err


def test_blocked_unsupported_scheme_redirect(redirect_server):
    """Verifies redirect attempting to switch to non-HTTP scheme is blocked."""
    url = f"{redirect_server}/unsupported-scheme-redirect"
    with pytest.raises(BlockedRedirectError) as exc_info:
        verify_target_reachability(url)
    err = str(exc_info.value).lower()
    assert "unsupported scheme" in err


def test_blocked_redirect_loop(redirect_server):
    """Verifies redirect loop exceeding limit raises BlockedRedirectError."""
    url = f"{redirect_server}/loop-redirect-1"
    with pytest.raises(BlockedRedirectError) as exc_info:
        verify_target_reachability(url, max_redirects=4)
    assert "exceeded maximum redirect limit" in str(exc_info.value).lower()


# ==============================================================================
# 4. Reusable Local-Target Authorization Policy (Requirements 4, 8)
# ==============================================================================

def test_policy_gate_reusable_local_policy_allows_arbitrary_ports():
    """Reusable local-target policy authorizes loopback on any valid TCP port."""
    gate = PolicyGate.create_local_target_policy()

    arbitrary_local_targets = [
        "http://localhost:3000",
        "http://localhost:3000/rest/user",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8000/api/sdg",
        "http://localhost:5173",
        "http://localhost:5173/dashboard",
        "http://127.0.0.1:8080/admin",
        "http://host.docker.internal:9000",
        "http://[::1]:11434/api/tags",
        "http://127.0.0.2:4200/feed",
    ]

    for url in arbitrary_local_targets:
        mock_finding = {
            "id": "TEST-ARB-PORT",
            "title": "Local Target Alert",
            "affected_asset": {"url": url},
            "suggested_action": "inspect_related_endpoint",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "ALLOW", f"Expected ALLOW for {url}, got {res['decision']}: {res['reason']}"
        assert "within authorized scope" in res["reason"]


def test_policy_gate_reusable_local_policy_denies_remote_targets():
    """Reusable local-target policy strictly denies remote and bypass targets."""
    gate = PolicyGate.create_local_target_policy()

    unauthorized_targets = [
        "http://example.com:8000",
        "http://target.local:3000",
        "http://internal.corp:5173",
        "http://localhost.evil.com:8000",
        "http://127.0.0.1.nip.io:8000",
        "http://localhost:3000@evil.com",
        "file:///etc/passwd",
        "ftp://localhost:8000",
    ]

    for url in unauthorized_targets:
        mock_finding = {
            "id": "TEST-UNAUTH",
            "title": "Remote / Bypass Alert",
            "affected_asset": {"url": url},
            "suggested_action": "manual_review",
        }
        res = gate.evaluate_finding(mock_finding)
        assert res["decision"] == "DENY", f"Expected DENY for {url}, got {res['decision']}"


def test_policy_gate_explicit_single_port_restriction_preserved():
    """Explicit single-port scope strictly restricts to specified port (backwards compatibility)."""
    gate = PolicyGate(authorized_scopes=["http://localhost:3000"])

    # Port 3000 should be allowed
    assert gate.is_in_scope("http://localhost:3000/api") is True
    assert gate.is_in_scope("http://127.0.0.1:3000/login") is True

    # Other ports must be denied
    assert gate.is_in_scope("http://localhost:8000/api") is False
    assert gate.is_in_scope("http://127.0.0.1:5173/dashboard") is False


# ==============================================================================
# 5. MasterOrchestrator Target Architecture Integration (Requirement 1, 6)
# ==============================================================================

def test_orchestrator_dynamic_target_mapping():
    """Orchestrator dynamically initializes target, container mapping, and policy gate."""
    orch_8000 = MasterOrchestrator(
        target_url="http://127.0.0.1:8000",
        use_sample=True,
    )
    assert orch_8000.target_url == "http://127.0.0.1:8000"
    assert orch_8000.container_target_url == "http://host.docker.internal:8000"
    # Authorized policy gate permits port 8000
    assert orch_8000.policy_gate.is_in_scope("http://127.0.0.1:8000/api") is True
    assert orch_8000.policy_gate.is_in_scope("http://localhost:8000/api") is True
    # Denies remote host
    assert orch_8000.policy_gate.is_in_scope("http://evil.com:8000") is False

    orch_5173 = MasterOrchestrator(
        target_url="http://localhost:5173",
        use_sample=True,
    )
    assert orch_5173.target_url == "http://localhost:5173"
    assert orch_5173.container_target_url == "http://host.docker.internal:5173"
    assert orch_5173.policy_gate.is_in_scope("http://localhost:5173/feed") is True


# ==============================================================================
# 6. Docker Container Connectivity Check (Requirement 5, 7)
# ==============================================================================

def test_docker_connectivity_live_and_failure():
    """Tests container-to-host connectivity check against running and dead ports."""
    # Live target on port 3000 (Juice Shop is active)
    ok, msg = verify_docker_container_connectivity("http://host.docker.internal:3000", timeout=4.0)
    assert ok is True
    assert "verified" in msg.lower()

    # Dead port should raise DockerConnectivityError
    with pytest.raises(DockerConnectivityError) as exc_info:
        verify_docker_container_connectivity("http://host.docker.internal:59997", timeout=2.0)
    assert "cannot reach target" in str(exc_info.value).lower()
