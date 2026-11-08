#!/usr/bin/env python3
"""
Project Zero-Day: Nuclei Scanner Normalizer
Script: app/nuclei_normalizer.py
Objective: Parse ProjectDiscovery Nuclei JSONL output into Project Zero-Day
           canonical finding schema.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse


def canonicalize_url(raw_url: str, canonical_host: Optional[str] = None) -> str:
    """
    Canonicalizes container loopback targets (e.g. host.docker.internal:<port>)
    back to standard localhost:<port> or specified canonical_host for consistent asset inventory.
    Strictly preserves the finding's original port.
    """
    if not raw_url:
        return ""
    try:
        parsed = urllib.parse.urlparse(raw_url)
        netloc = parsed.netloc.lower()
        if "host.docker.internal" in netloc or "127.0.0.1" in netloc or "localhost" in netloc:
            port_part = f":{parsed.port}" if parsed.port is not None else ""
            if canonical_host:
                if ":" in canonical_host:
                    c_host, c_port_str = canonical_host.split(":", 1)
                    if parsed.port is not None and str(parsed.port) == c_port_str:
                        new_netloc = canonical_host
                    elif parsed.port is None:
                        new_netloc = canonical_host
                    else:
                        new_netloc = f"{c_host}{port_part}"
                else:
                    new_netloc = f"{canonical_host}{port_part}"
            else:
                new_netloc = f"localhost{port_part}"
            parsed = parsed._replace(netloc=new_netloc)
            return urllib.parse.urlunparse(parsed)
    except Exception:
        pass
    return raw_url


def map_nuclei_severity(raw_sev: str) -> str:
    """Map Nuclei severity strings to Project Zero-Day taxonomy."""
    s = (raw_sev or "").strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }
    return mapping.get(s, "Informational")


def extract_cwe_id(classification: Dict[str, Any]) -> Optional[str]:
    """Extract standard CWE-XXX string from Nuclei classification dictionary."""
    if not isinstance(classification, dict):
        return None
    cwe_field = classification.get("cwe-id", [])
    if isinstance(cwe_field, list) and cwe_field:
        first = str(cwe_field[0]).strip().upper()
        return first if first.startswith("CWE-") else f"CWE-{first}"
    elif isinstance(cwe_field, str) and cwe_field:
        first = cwe_field.strip().upper()
        return first if first.startswith("CWE-") else f"CWE-{first}"
    return None


def generate_nuclei_finding_id(template_id: str, matched_at: str, index: int) -> str:
    """Generate deterministic unique ID for Nuclei finding."""
    seed = f"NUC:{template_id}:{matched_at}:{index}".encode("utf-8")
    hash_digest = hashlib.sha256(seed).hexdigest()[:8]
    clean_tid = template_id.replace("/", "-").replace("_", "-")[:20]
    return f"NUC-{clean_tid}-{hash_digest}"


def normalize_nuclei_record(
    record: Dict[str, Any],
    index: int,
    source_filename: str,
    canonical_host: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize a single Nuclei JSON object into the canonical finding schema."""
    template_id = str(record.get("template-id") or record.get("templateID") or "generic").strip()
    info = record.get("info") or {}
    title = str(info.get("name") or template_id)
    raw_severity = str(info.get("severity") or "info")
    risk_rating = map_nuclei_severity(raw_severity)
    cwe_id = extract_cwe_id(info.get("classification") or {})

    matched_at = str(record.get("matched-at") or record.get("host") or "").strip()
    canonical_url = canonicalize_url(matched_at, canonical_host=canonical_host)

    finding_id = generate_nuclei_finding_id(template_id, matched_at, index)

    # Extract method
    curl_cmd = str(record.get("curl-command") or "")
    method = "GET"
    if "-X POST" in curl_cmd or "POST " in str(record.get("request", "")):
        method = "POST"
    elif "-X PUT" in curl_cmd:
        method = "PUT"
    elif "-X DELETE" in curl_cmd:
        method = "DELETE"

    extracted = record.get("extracted-results") or []
    extracted_str = ", ".join(str(e) for e in extracted) if isinstance(extracted, list) else str(extracted)

    evidence_dict = {
        "observed_at": None,  # Invariant: pending verification
        "attack": extracted_str or curl_cmd[:120],
        "evidence": extracted_str or record.get("matcher-name") or "Matched Nuclei pattern",
        "other_info": f"Template: {template_id} | Type: {record.get('type', 'http')}",
        "request": record.get("request"),
        "response": record.get("response"),
    }

    verification_dict = {
        "status": "NEEDS_VERIFICATION",
        "verified": False,
        "verified_at": None,
        "verified_by": None,
        "method": None,
        "notes": "Nuclei alert initialized; pending verification evaluation",
    }

    references = info.get("reference") or []
    ref_url = references[0] if (isinstance(references, list) and references) else (str(references) if references else "")

    ai_advisory = {
        "recommendation": str(info.get("remediation") or ""),
        "reference": ref_url,
        "remediation_guidance": None,
        "analysis": None,
    }

    provenance = {
        "scanner": "ProjectDiscovery Nuclei",
        "source_file": source_filename,
        "template_id": template_id,
        "template_version": str(info.get("version") or "1.0"),
        "raw_matched_at": matched_at,
        "matcher_name": str(record.get("matcher-name") or ""),
        "curl_command": curl_cmd,
        "run_id": run_id,
    }

    return {
        "id": finding_id,
        "source_type": "web",
        "source_tool": "ProjectDiscovery Nuclei",
        "title": title,
        "cwe_id": cwe_id,
        "risk_rating": risk_rating,
        "priority": None,  # Populated downstream in Stage 2
        "affected_asset": {
            "url": canonical_url,
            "method": method,
            "parameter": str(record.get("extracted-results", [""])[0]) if extracted else "",
        },
        "description": str(info.get("description") or title),
        "evidence": evidence_dict,
        "verification": verification_dict,
        "ai_advisory": ai_advisory,
        "provenance": provenance,
    }


def normalize_nuclei_findings(
    input_path: Any,
    output_path: Optional[Any] = None,
    canonical_host: Optional[str] = None,
    expected_target_url: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Read streaming JSONL file from Nuclei scan and return normalized finding list.
    Validates findings against expected_target_url and quarantines cross-target / port-mismatched findings.
    """
    input_path = Path(input_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"Nuclei output file not found: {input_path}")
    if output_path:
        output_path = Path(output_path)

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

    normalized = []
    quarantined_count = 0
    idx = 0
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            clean_line = line.strip()
            if not clean_line:
                continue
            try:
                record = json.loads(clean_line)
                if isinstance(record, dict) and ("template-id" in record or "templateID" in record):
                    norm = normalize_nuclei_record(
                        record,
                        idx,
                        input_path.name,
                        canonical_host=canonical_host,
                        run_id=run_id,
                    )

                    # Target Isolation Guard: verify finding's URL matches expected target
                    if expected_host is not None and expected_port is not None:
                        try:
                            f_url = norm.get("affected_asset", {}).get("url", "")
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
                                    f"[WARN] Quarantining mismatched Nuclei finding '{norm.get('title')}' "
                                    f"on {f_url} (port {f_port} != expected port {expected_port} of {expected_target_url})."
                                )
                                continue
                        except Exception:
                            pass

                    normalized.append(norm)
                    idx += 1
            except json.JSONDecodeError:
                continue

    if quarantined_count > 0:
        print(f"[*] Quarantined {quarantined_count} mismatched Nuclei finding(s).")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)

    return normalized


if __name__ == "__main__":
    import sys
    in_p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/nuclei-findings-live.jsonl")
    out_p = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("artifacts/normalized-nuclei.json")
    res = normalize_nuclei_findings(in_p, out_p)
    print(f"Normalized {len(res)} Nuclei findings -> {out_p}")
