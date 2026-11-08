#!/usr/bin/env python3
"""
Project Zero-Day - Stage 1 & Milestone 2: Evidence Verification Engine
Script: app/verification_engine.py
Objective: Evaluate normalized and prioritized findings for verification status using
           a rigorous 4-state taxonomy:
           - CONFIRMED: Supported by reproducible defensive evidence (e.g. read-only HTTP probe).
           - REJECTED: Disproven by live evidence (e.g. claimed missing header is present).
           - NEEDS_VERIFICATION: Insufficient evidence, offline fixture, or unprobed asset.
           - MANUAL_REVIEW: High-risk injection/execution flaws requiring human penetration testing
                            per safety invariants (active offensive payloads prohibited).
"""

import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


VALID_VERIFICATION_STATUSES = {
    "CONFIRMED",
    "REJECTED",
    "NEEDS_VERIFICATION",
    "MANUAL_REVIEW",
}


def resolve_file_path(filename: str, search_dirs: Optional[List[Path]] = None) -> Path:
    """
    Dynamically locate input files across repo root, current directory, and app directory.
    """
    if search_dirs is None:
        root_dir = Path(__file__).resolve().parent.parent
        app_dir = Path(__file__).resolve().parent
        search_dirs = [
            Path.cwd(),
            root_dir,
            app_dir,
            Path("C:/ZeroDay"),
            Path("C:/zrd"),
        ]

    for directory in search_dirs:
        candidate = directory / filename
        if candidate.is_file():
            return candidate

    return Path.cwd() / filename


def _normalize_probe_url(raw_url: str, default_target: str = "http://localhost:3000") -> str:
    """
    Normalizes URLs for host-side probing, translating container aliases to localhost.
    """
    if not raw_url:
        return default_target

    url = raw_url.strip()
    if "host.docker.internal" in url:
        url = url.replace("host.docker.internal", "localhost")
    return url


def _defensive_http_probe(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> Tuple[Optional[int], Dict[str, str], str, str]:
    """
    Executes a defensive, read-only HTTP probe against the target URL.
    Returns: (status_code, response_headers_dict_lower, body_snippet, final_url)
    """
    req_headers = {
        "User-Agent": "ZeroDay-EvidenceVerifier/2.0 (Defensive Security Audit)",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            final_url = resp.geturl()
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body_bytes = resp.read(4096)
            body_snippet = body_bytes.decode("utf-8", errors="replace")
            return status, resp_headers, body_snippet, final_url
    except urllib.error.HTTPError as err:
        status = err.code
        final_url = err.geturl() if hasattr(err, "geturl") else url
        resp_headers = {k.lower(): v for k, v in err.headers.items()}
        try:
            body_bytes = err.read(2048)
            body_snippet = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_snippet = ""
        return status, resp_headers, body_snippet, final_url
    except Exception as exc:
        return None, {}, f"Probe error: {exc}", url


def verify_finding_evidence(
    finding: Dict[str, Any],
    target_base_url: str = "http://localhost:3000",
    policy_gate: Any = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    Performs active evidence verification on a finding against authorized live targets.
    Classifies into CONFIRMED, REJECTED, MANUAL_REVIEW, or NEEDS_VERIFICATION.
    Attaches cryptographic hashes, observation timestamps, and structured evidence.
    """
    f_id = finding.get("id", "UNKNOWN")
    title = finding.get("title", "")
    cwe_id = (finding.get("cwe_id") or "").upper()
    asset = finding.get("affected_asset", {})
    raw_url = asset.get("url") or target_base_url
    probe_url = _normalize_probe_url(raw_url, default_target=target_base_url)

    # 1. Authoritative Policy Gate verification
    if policy_gate is not None:
        in_scope = policy_gate.is_in_scope(probe_url)
        if not in_scope:
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": None,
                "verified_by": None,
                "verification_method": "policy_scope_invariant",
                "evaluation_notes": f"Target URL '{probe_url}' outside authorized policy scope; active probe prohibited.",
            }

    # 2. Safety Invariant: High-risk injection / execution vulnerabilities require manual review
    # Active attack payloads or exploit scripts are strictly prohibited by zero-day guardrails.
    manual_review_cwes = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-94", "CWE-434", "CWE-352", "CWE-918", "CWE-749", "CWE-95"}
    title_lower = title.lower()
    if (
        cwe_id in manual_review_cwes
        or "sql injection" in title_lower
        or "cross site scripting" in title_lower
        or "command injection" in title_lower
        or "directory traversal" in title_lower
        or "remote code execution" in title_lower
        or "dangerous js" in title_lower
        or "dangerous functions" in title_lower
    ):
        return {
            "status": "MANUAL_REVIEW",
            "verified": False,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "verified_by": "zero-day-safety-gate",
            "verification_method": "safety_gate_manual_review",
            "evidence": {
                "cwe_id": cwe_id,
                "target_url": probe_url,
                "reason": "Active exploitation prohibited by safety policy",
            },
            "evaluation_notes": (
                f"Manual review required: High-severity finding ({cwe_id} - '{title}') requires "
                "authorized human penetration testing. Offensive exploit generation is blocked by policy."
            ),
        }

    # 3. Read-only defensive probes for headers and exposed endpoints
    status_code, resp_headers, body_snippet, final_url = _defensive_http_probe(probe_url, timeout=timeout)

    now_utc = datetime.now(timezone.utc).isoformat()

    if status_code is None:
        return {
            "status": "NEEDS_VERIFICATION",
            "verified": False,
            "verified_at": now_utc,
            "verified_by": "zero-day-evidence-verifier",
            "verification_method": "network_probe_unreachable",
            "evaluation_notes": f"Endpoint unreachable during verification probe ({body_snippet}); remains NEEDS_VERIFICATION.",
        }

    # Redirect policy scope check
    if policy_gate is not None and final_url != probe_url:
        if not policy_gate.is_in_scope(final_url):
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "policy_scope_invariant",
                "evaluation_notes": f"Probe redirected to out-of-scope target '{final_url}'; active evaluation prohibited.",
            }

    # Helper to compute SHA-256 evidence fingerprint
    def make_evidence_hash(data_str: str) -> str:
        return hashlib.sha256(data_str.encode("utf-8")).hexdigest()[:16]

    # --- Rule A: Content Security Policy (CSP) ---
    if "content security policy" in title_lower or cwe_id == "CWE-693" and "csp" in title_lower:
        # Phase 3 Requirement: Do not confirm missing header vulnerabilities on 404 Not Found or error responses
        if status_code == 404:
            ev_data = f"url:{probe_url}|status:404|not_found"
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": 404,
                    "missing_header": "Content-Security-Policy",
                    "observed_headers": list(resp_headers.keys()),
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": (
                    "Inconclusive/Unverified: Target endpoint returned HTTP 404 Not Found. "
                    "A missing security header cannot be inferred as an application vulnerability on a non-existent or error resource."
                ),
            }
        elif status_code >= 400:
            ev_data = f"url:{probe_url}|status:{status_code}|error_response"
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "missing_header": "Content-Security-Policy",
                    "observed_headers": list(resp_headers.keys()),
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": (
                    f"Inconclusive/Unverified: Target endpoint returned HTTP {status_code} error response. "
                    "Header evaluation requires a valid application response."
                ),
            }

        csp_present = "content-security-policy" in resp_headers or "content-security-policy-report-only" in resp_headers
        if not csp_present:
            ev_data = f"url:{probe_url}|status:{status_code}|csp_missing"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "missing_header": "Content-Security-Policy",
                    "observed_headers": list(resp_headers.keys()),
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": (
                    f"Confirmed: Target endpoint returned valid application response (HTTP {status_code}) without Content-Security-Policy header."
                ),
            }
        else:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "configured_header": "Content-Security-Policy",
                    "observed_headers": list(resp_headers.keys()),
                    "observed_at": now_utc,
                },
                "evaluation_notes": (
                    f"Rejected: Content-Security-Policy header is present in server response ({resp_headers.get('content-security-policy') or resp_headers.get('content-security-policy-report-only')})."
                ),
            }

    # --- Rule B: X-Frame-Options / Clickjacking ---
    if "x-frame-options" in title_lower or "anti-clickjacking" in title_lower or cwe_id == "CWE-1021":
        if status_code == 404:
            ev_data = f"url:{probe_url}|status:404|not_found"
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": 404,
                    "missing_header": "X-Frame-Options",
                    "observed_headers": list(resp_headers.keys()),
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": "Inconclusive/Unverified: Target endpoint returned HTTP 404 Not Found. Missing frame protection cannot be verified on a non-existent resource.",
            }
        elif status_code >= 400:
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Inconclusive/Unverified: Target endpoint returned HTTP {status_code} error response.",
            }

        xfo = resp_headers.get("x-frame-options")
        csp = resp_headers.get("content-security-policy", "")
        has_frame_protection = (xfo is not None) or ("frame-ancestors" in csp)
        if not has_frame_protection:
            ev_data = f"url:{probe_url}|status:{status_code}|xfo_missing"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "missing_header": "X-Frame-Options",
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": f"Confirmed: Target returned HTTP {status_code} without X-Frame-Options or frame-ancestors.",
            }
        else:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Rejected: Frame protection is actively configured (X-Frame-Options: '{xfo}').",
            }

    # --- Rule C: Cross-Domain Misconfiguration (Wildcard CORS) ---
    if "cross-domain" in title_lower or "cors" in title_lower or cwe_id == "CWE-942":
        if status_code >= 400:
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Inconclusive/Unverified: Target endpoint returned HTTP {status_code} error response.",
            }
        acao = resp_headers.get("access-control-allow-origin")
        if acao == "*" or (acao and "null" in acao):
            ev_data = f"url:{probe_url}|status:{status_code}|cors_wildcard:{acao}"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "access_control_allow_origin": acao,
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": f"Confirmed: Target endpoint returned overly permissive CORS header (Access-Control-Allow-Origin: '{acao}').",
            }
        else:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": "Rejected: Access-Control-Allow-Origin header is not wildcard or permissive.",
            }

    # --- Rule D: COEP / COOP Security Headers ---
    if "embedder-policy" in title_lower or "coep" in title_lower:
        if status_code >= 400:
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Inconclusive/Unverified: Target endpoint returned HTTP {status_code} error response.",
            }
        coep = resp_headers.get("cross-origin-embedder-policy")
        if not coep:
            ev_data = f"url:{probe_url}|status:{status_code}|coep_missing"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "missing_header": "Cross-Origin-Embedder-Policy",
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": f"Confirmed: Target endpoint returned HTTP {status_code} without Cross-Origin-Embedder-Policy header.",
            }
        else:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Rejected: Cross-Origin-Embedder-Policy is present ({coep}).",
            }

    if "opener-policy" in title_lower or "coop" in title_lower:
        if status_code >= 400:
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Inconclusive/Unverified: Target endpoint returned HTTP {status_code} error response.",
            }
        coop = resp_headers.get("cross-origin-opener-policy")
        if not coop:
            ev_data = f"url:{probe_url}|status:{status_code}|coop_missing"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "missing_header": "Cross-Origin-Opener-Policy",
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": f"Confirmed: Target endpoint returned HTTP {status_code} without Cross-Origin-Opener-Policy header.",
            }
        else:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Rejected: Cross-Origin-Opener-Policy is present ({coop}).",
            }

    # --- Rule E: Deprecated Feature-Policy ---
    if "feature policy" in title_lower or "feature-policy" in title_lower:
        if status_code >= 400:
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": f"Inconclusive/Unverified: Target endpoint returned HTTP {status_code} error response.",
            }
        fp = resp_headers.get("feature-policy")
        if fp:
            ev_data = f"url:{probe_url}|status:{status_code}|feature_policy_present:{fp}"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "final_url": final_url,
                    "http_status": status_code,
                    "feature_policy_header": fp,
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": f"Confirmed: Deprecated Feature-Policy header observed on endpoint ('{fp}'). Migrate to Permissions-Policy.",
            }
        else:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_header_assertion",
                "evaluation_notes": "Rejected: Feature-Policy header is absent.",
            }

    # --- Rule C: Public Swagger / OpenAPI Route Detection ---
    if "swagger" in title_lower or "openapi" in title_lower or "api-docs" in probe_url or cwe_id == "CWE-200" and "swagger" in title_lower:
        body_lower = body_snippet.lower()
        is_swagger = (
            status_code == 200
            and ("swagger" in body_lower or "openapi" in body_lower or "swagger-ui" in body_lower or "paths:" in body_lower)
        )
        if is_swagger:
            ev_data = f"url:{probe_url}|status:{status_code}|swagger_detected"
            return {
                "status": "CONFIRMED",
                "verified": True,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_route_assertion",
                "evidence": {
                    "probed_url": probe_url,
                    "http_status": status_code,
                    "matched_pattern": "Public Swagger API UI/JSON",
                    "evidence_hash": make_evidence_hash(ev_data),
                    "observed_at": now_utc,
                },
                "evaluation_notes": f"Confirmed: Public Swagger API documentation accessible at {probe_url} (HTTP {status_code}).",
            }
        elif status_code in [404, 403, 401]:
            return {
                "status": "REJECTED",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_route_assertion",
                "evaluation_notes": f"Rejected: Swagger route returned HTTP {status_code} (resource inaccessible).",
            }

    # --- Rule D: Cookie Flags (SameSite, HttpOnly, Secure) ---
    if "samesite" in title_lower or cwe_id == "CWE-1275" or "cookie" in title_lower:
        set_cookie = resp_headers.get("set-cookie", "")
        if set_cookie:
            missing_samesite = "samesite" not in set_cookie.lower()
            if missing_samesite:
                ev_data = f"url:{probe_url}|status:{status_code}|cookie_no_samesite"
                return {
                    "status": "CONFIRMED",
                    "verified": True,
                    "verified_at": now_utc,
                    "verified_by": "zero-day-evidence-verifier",
                    "verification_method": "defensive_cookie_assertion",
                    "evidence": {
                        "probed_url": probe_url,
                        "http_status": status_code,
                        "cookie_snippet": set_cookie[:100],
                        "evidence_hash": make_evidence_hash(ev_data),
                        "observed_at": now_utc,
                    },
                    "evaluation_notes": "Confirmed: Set-Cookie header lacks SameSite attribute.",
                }
            else:
                return {
                    "status": "REJECTED",
                    "verified": False,
                    "verified_at": now_utc,
                    "verified_by": "zero-day-evidence-verifier",
                    "verification_method": "defensive_cookie_assertion",
                    "evaluation_notes": "Rejected: SameSite attribute is properly set on cookies.",
                }
        else:
            # No cookies issued on probed URL; maintain NEEDS_VERIFICATION
            return {
                "status": "NEEDS_VERIFICATION",
                "verified": False,
                "verified_at": now_utc,
                "verified_by": "zero-day-evidence-verifier",
                "verification_method": "defensive_cookie_assertion",
                "evaluation_notes": "Target endpoint issued no Set-Cookie headers on GET; session-specific verification needed.",
            }

    # --- Rule E: Default / Unclassified Alert ---
    return {
        "status": "NEEDS_VERIFICATION",
        "verified": False,
        "verified_at": now_utc,
        "verified_by": "zero-day-evidence-verifier",
        "verification_method": "unclassified_scanner_alert",
        "evaluation_notes": "Unclassified scanner alert without automated defensive probe; maintained in NEEDS_VERIFICATION.",
    }


def evaluate_finding_verification(
    finding: Dict[str, Any],
    live_verification: bool = False,
    target_url: str = "http://localhost:3000",
    policy_gate: Any = None,
) -> Dict[str, Any]:
    """
    Evaluates individual finding against verification criteria.
    - If live_verification is True: Runs active defensive verification routines.
    - If live_verification is False (sample/offline mode): Enforces negative invariant
      (NEEDS_VERIFICATION, verified: False).
    """
    if live_verification:
        verif_data = verify_finding_evidence(
            finding,
            target_base_url=target_url,
            policy_gate=policy_gate,
        )
    else:
        # Deliberately maintained in NEEDS_VERIFICATION status for sample/offline fixtures
        verif_data = {
            "status": "NEEDS_VERIFICATION",
            "verified": False,
            "verified_at": None,
            "verified_by": None,
            "evaluation_notes": (
                "Scanner alert lacks explicit observed_at metadata; "
                "maintained in NEEDS_VERIFICATION status per Zero-Day protocol."
            ),
        }

    finding["verification"] = verif_data
    # Preserve original scanner evidence in finding["evidence"] and append verification evidence
    if "evidence" in verif_data:
        finding["verification_evidence"] = verif_data["evidence"]
    return finding


def run_verification_engine(
    input_path: Path,
    output_path: Path,
    live_verification: bool = False,
    target_url: str = "http://localhost:3000",
    policy_gate: Any = None,
) -> List[Dict[str, Any]]:
    """
    FR-05 & Milestone 2: Evaluates findings and writes verification_results.json.
    """
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found at: {input_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings", [])
    else:
        raise ValueError(f"Unexpected JSON format in {input_path}: expected list or dict.")

    status_counter: Counter = Counter()
    verified_counter: Counter = Counter()
    verified_results: List[Dict[str, Any]] = []

    for finding in findings:
        evaluated = evaluate_finding_verification(
            finding,
            live_verification=live_verification,
            target_url=target_url,
            policy_gate=policy_gate,
        )
        verified_results.append(evaluated)

        v_status = evaluated.get("verification", {}).get("status", "UNKNOWN")
        v_bool = evaluated.get("verification", {}).get("verified", False)
        status_counter[v_status] += 1
        verified_counter[v_bool] += 1

    # Write output to verification_results.json
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(verified_results, f, indent=2)

    # UI/UX Logging
    total_evaluated = len(verified_results)
    print("============================================================")
    print("Project Zero-Day: Verification Engine (Stage 1 & Milestone 2)")
    print("============================================================")
    print(f"Input file:                  {input_path}")
    print(f"Mode:                        {'LIVE ACTIVE VERIFICATION' if live_verification else 'OFFLINE / SAMPLE'}")
    print(f"Target URL:                  {target_url}")
    print(f"Total findings evaluated:    {total_evaluated}")
    print("Verification status distribution:")
    for status, count in status_counter.items():
        pct = (count / total_evaluated * 100) if total_evaluated > 0 else 0
        print(f"  - {status}: {count} ({pct:.1f}%)")
    print("Verified boolean breakdown:")
    print(f"  - verified: false:         {verified_counter[False]}")
    print(f"  - verified: true:          {verified_counter[True]}")
    print(f"Output written to:           {output_path}")
    print("Status:                      SUCCESS")
    print("============================================================")

    return verified_results


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Zero-Day Verification Engine")
    parser.add_argument("--live", action="store_true", help="Enable active live verification probes")
    parser.add_argument("--target", default="http://localhost:3000", help="Target base URL")
    parser.add_argument("--input", default=None, help="Input findings JSON file path")
    args = parser.parse_args()

    if args.input:
        input_file = Path(args.input)
    else:
        input_file = resolve_file_path("prioritized_findings.json")
        if not input_file.is_file():
            input_file = resolve_file_path("normalized_findings.json")

    root_dir = Path(__file__).resolve().parent.parent
    output_file = root_dir / "verification_results.json"

    try:
        results = run_verification_engine(
            input_path=input_file,
            output_path=output_file,
            live_verification=args.live,
            target_url=args.target,
        )
        if len(results) == 0:
            print("[WARN] Verification results count is 0.", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Verification engine execution failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
