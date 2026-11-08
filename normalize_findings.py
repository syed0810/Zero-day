#!/usr/bin/env python3
"""
Project Zero-Day - Stage 1: Finding Normalization Pipeline
Script: normalize_findings.py
Objective: Parse nested OWASP ZAP scanner output (site -> alerts -> instances)
           into normalized findings conforming to Project Zero-Day common schema.
"""

import hashlib
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional


def resolve_file_path(filename: str, search_dirs: Optional[List[Path]] = None) -> Path:
    """
    Dynamically resolve target file path across current directory, script parent directory,
    or fallback locations.
    """
    if search_dirs is None:
        search_dirs = [
            Path.cwd(),
            Path(__file__).resolve().parent,
            Path("C:/ZeroDay"),
            Path("C:/zrd"),
        ]

    for directory in search_dirs:
        candidate = directory / filename
        if candidate.is_file():
            return candidate

    # Default fallback to script parent directory
    return Path(__file__).resolve().parent / filename


def map_risk_rating(risk_code: Any, risk_desc: Optional[str] = None) -> str:
    """
    Normalize scanner risk rating to standard taxonomy:
    Critical, High, Medium, Low, Informational.
    """
    code_str = str(risk_code).strip()
    mapping = {
        "3": "High",
        "2": "Medium",
        "1": "Low",
        "0": "Informational",
    }
    if code_str in mapping:
        return mapping[code_str]

    if risk_desc:
        clean_desc = risk_desc.split("(")[0].strip().capitalize()
        if clean_desc in ["Critical", "High", "Medium", "Low", "Informational"]:
            return clean_desc

    return "Informational"


def generate_finding_id(plugin_id: str, alert_ref: str, uri: str, method: str, param: str, index: int) -> str:
    """
    Generate deterministic, unique finding identifier.
    """
    seed = f"{plugin_id}:{alert_ref}:{uri}:{method}:{param}:{index}".encode("utf-8")
    hash_digest = hashlib.sha256(seed).hexdigest()[:8]
    ref_tag = alert_ref or plugin_id or "GEN"
    return f"ZAP-{ref_tag}-{hash_digest}"


def normalize_instance(
    site: Dict[str, Any],
    alert: Dict[str, Any],
    instance: Dict[str, Any],
    instance_idx: int,
    source_filename: str,
    canonical_host: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    FR-02 & FR-03: Maps a single alert instance to the Project Zero-Day common finding schema.
    Preserves original port and provenance without synthetic target rewrites.
    """
    plugin_id = str(alert.get("pluginid", "")).strip()
    alert_ref = str(alert.get("alertRef", plugin_id)).strip()
    cwe_raw = str(alert.get("cweid", "")).strip()
    cwe_id = f"CWE-{cwe_raw}" if cwe_raw and not cwe_raw.upper().startswith("CWE-") else (cwe_raw or None)

    title = alert.get("name") or alert.get("alert") or "Untitled Scanner Alert"
    risk_code = alert.get("riskcode", "0")
    risk_desc = alert.get("riskdesc", "")
    risk_rating = map_risk_rating(risk_code, risk_desc)

    raw_uri = str(instance.get("uri", "")).strip()
    # Canonicalize container internal hostname (e.g. host.docker.internal:<port>) to host-accessible address
    # STRICT RULE: Preserve the finding's original port; never rewrite port to match a different target.
    uri = raw_uri
    try:
        parsed_u = urllib.parse.urlparse(raw_uri)
        netloc_lower = parsed_u.netloc.lower()
        if "host.docker.internal" in netloc_lower or "127.0.0.1" in netloc_lower or (canonical_host and "target.local" in netloc_lower):
            if canonical_host and ("target.local" in netloc_lower or "host.docker.internal" in netloc_lower):
                if ":" not in canonical_host and parsed_u.port:
                    new_netloc = f"{canonical_host}:{parsed_u.port}"
                else:
                    new_netloc = canonical_host
            else:
                port_suffix = f":{parsed_u.port}" if parsed_u.port is not None else ""
                new_netloc = f"localhost{port_suffix}"
            uri = urllib.parse.urlunparse(parsed_u._replace(netloc=new_netloc))
    except Exception:
        pass

    method = str(instance.get("method", "GET")).strip().upper() or "GET"
    param = str(instance.get("param", "")).strip()

    finding_id = generate_finding_id(plugin_id, alert_ref, uri, method, param, instance_idx)

    # FR-03: Set evidence.observed_at to null by default (deliberately keeping in NEEDS_VERIFICATION)
    evidence_dict = {
        "observed_at": None,
        "attack": instance.get("attack", ""),
        "evidence": instance.get("evidence", ""),
        "other_info": instance.get("otherinfo", "") or alert.get("otherinfo", ""),
        "request": instance.get("request", None),
        "response": instance.get("response", None),
    }

    # Hard Constraint: Never auto-mark scanner alerts as verified: true
    verification_dict = {
        "status": "NEEDS_VERIFICATION",
        "verified": False,
        "verified_at": None,
        "verified_by": None,
        "method": None,
        "notes": "Scanner alert initialized; pending verification evaluation",
    }

    ai_advisory = {
        "recommendation": alert.get("solution", ""),
        "reference": alert.get("reference", ""),
        "remediation_guidance": None,
        "analysis": None,
    }

    is_live = "live" in source_filename.lower() or "zap-findings-live" in source_filename.lower()
    provenance_label = "LIVE SCAN: OWASP ZAP" if is_live else "SAMPLE FIXTURE: OWASP ZAP"

    provenance = {
        "scanner": "OWASP ZAP",
        "provenance_label": provenance_label,
        "source_file": source_filename,
        "plugin_id": plugin_id,
        "alert_ref": alert_ref,
        "source_id": str(alert.get("sourceid", "")).strip(),
        "site_name": site.get("@name", ""),
        "site_host": site.get("@host", ""),
        "site_port": site.get("@port", ""),
        "site_ssl": site.get("@ssl", ""),
        "raw_uri": raw_uri,
        "run_id": run_id,
    }

    return {
        "id": finding_id,
        "source_type": "web",
        "source_tool": "OWASP ZAP",
        "title": title,
        "cwe_id": cwe_id,
        "risk_rating": risk_rating,
        "priority": None,  # Populated downstream by decision_engine.py
        "affected_asset": {
            "url": uri,
            "method": method,
            "parameter": param,
        },
        "description": alert.get("desc", ""),
        "evidence": evidence_dict,
        "verification": verification_dict,
        "ai_advisory": ai_advisory,
        "provenance": provenance,
    }


def normalize_zap_findings(
    input_path: Path,
    output_path: Path,
    canonical_host: Optional[str] = None,
    expected_target_url: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    FR-01: Safely iterates through data['site'] -> alerts -> instances in zap-findings.json
    without raising KeyError on missing or heterogeneous fields.
    Validates findings against expected_target_url and quarantines cross-target / port-mismatched findings.
    """
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found at: {input_path}")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_sites_count = 0
    raw_alerts_count = 0
    raw_instances_count = 0
    quarantined_count = 0
    normalized_findings: List[Dict[str, Any]] = []

    # Parse expected target if provided
    expected_host = None
    expected_port = None
    if expected_target_url:
        try:
            parsed_exp = urllib.parse.urlparse(expected_target_url)
            expected_host = (parsed_exp.hostname or "").lower()
            expected_port = parsed_exp.port or (443 if parsed_exp.scheme.lower() == "https" else 80)
        except Exception:
            pass

    LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}

    # Handle heterogeneous site structure: single dict or list of dicts
    sites_raw = data.get("site", [])
    if isinstance(sites_raw, dict):
        sites = [sites_raw]
    elif isinstance(sites_raw, list):
        sites = sites_raw
    else:
        sites = []

    for site in sites:
        if not isinstance(site, dict):
            continue
        raw_sites_count += 1

        alerts_raw = site.get("alerts", [])
        if isinstance(alerts_raw, dict):
            alerts = [alerts_raw]
        elif isinstance(alerts_raw, list):
            alerts = alerts_raw
        else:
            alerts = []

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            raw_alerts_count += 1

            instances_raw = alert.get("instances", [])
            if isinstance(instances_raw, dict):
                instances = [instances_raw]
            elif isinstance(instances_raw, list):
                instances = instances_raw
            else:
                instances = []

            for idx, instance in enumerate(instances):
                if not isinstance(instance, dict):
                    continue
                raw_instances_count += 1

                finding = normalize_instance(
                    site=site,
                    alert=alert,
                    instance=instance,
                    instance_idx=idx,
                    source_filename=input_path.name,
                    canonical_host=canonical_host,
                    run_id=run_id,
                )

                # Target Isolation Guard: verify finding's URL matches expected target
                if expected_host is not None and expected_port is not None:
                    try:
                        f_url = finding.get("affected_asset", {}).get("url", "")
                        parsed_f = urllib.parse.urlparse(f_url)
                        f_host = (parsed_f.hostname or "").lower()
                        f_port = parsed_f.port or (443 if parsed_f.scheme.lower() == "https" else 80)

                        is_exp_loopback = expected_host in LOOPBACK_HOSTS
                        is_f_loopback = f_host in LOOPBACK_HOSTS

                        if is_exp_loopback and is_f_loopback:
                            target_matches = (f_port == expected_port)
                        else:
                            target_matches = (f_host == expected_host and f_port == expected_port)

                        if not target_matches:
                            quarantined_count += 1
                            print(
                                f"[WARN] Quarantining mismatched ZAP finding '{finding.get('title')}' "
                                f"on {f_url} (port {f_port} != expected port {expected_port} of {expected_target_url})."
                            )
                            continue
                    except Exception:
                        pass

                normalized_findings.append(finding)

    # Write output to normalized_findings.json
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(normalized_findings, f, indent=2)

    # UI/UX Logging
    print("============================================================")
    print("Project Zero-Day: Finding Normalizer (Stage 1)")
    print("============================================================")
    print(f"Input file:                  {input_path}")
    print(f"Total raw sites parsed:      {raw_sites_count}")
    print(f"Total raw alerts inspected:  {raw_alerts_count}")
    print(f"Total raw instances parsed:  {raw_instances_count}")
    if quarantined_count > 0:
        print(f"Quarantined out-of-scope:    {quarantined_count}")
    print(f"Total normalized findings:   {len(normalized_findings)}")
    print(f"Output written to:           {output_path}")
    print("Status:                      SUCCESS")
    print("============================================================")

    return normalized_findings


# Alias for backwards compatibility
normalize_zap_file = normalize_zap_findings


def main() -> None:
    # Resolve input and output file paths dynamically
    input_arg = sys.argv[1] if len(sys.argv) > 1 else "zap-findings.json"
    input_file = resolve_file_path(input_arg)
    output_file = input_file.parent / "normalized_findings.json"

    try:
        findings = normalize_zap_findings(input_file, output_file)
        if len(findings) == 0:
            print("[WARN] Normalized findings count is 0. Please verify input data.", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Failed during normalization: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
