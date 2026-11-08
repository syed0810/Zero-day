#!/usr/bin/env python3
"""
Project Zero-Day: Multi-Scanner Finding Deduplicator
Script: app/finding_deduplicator.py
Objective: Correlate and merge overlapping findings between OWASP ZAP and Nuclei
           without losing raw evidence or inflating vulnerability counts.
"""

from collections import defaultdict
import hashlib
from typing import Any, Dict, List, Tuple
import urllib.parse


def normalize_vuln_category(title: str, cwe_id: str) -> str:
    """Normalize vulnerability title and CWE into a canonical equivalence class."""
    t = (title or "").lower()
    c = (cwe_id or "").upper()

    if "cwe-79" in c or "xss" in t or "cross site scripting" in t or "cross-site scripting" in t:
        return "XSS"
    if "cwe-89" in c or "sql injection" in t or "sqli" in t:
        return "SQLI"
    if "cwe-1021" in c or "clickjacking" in t or "x-frame-options" in t or "frame-ancestors" in t:
        return "CLICKJACKING"
    if "cwe-693" in c or "content security policy" in t or "csp" in t:
        return "CSP_MISCONFIG"
    if "cwe-1275" in c or "samesite" in t or "cookie" in t:
        return "COOKIE_SECURITY"
    if "cwe-200" in c or "information disclosure" in t or "tech-detect" in t:
        return "INFO_DISCLOSURE"
    if "cors" in t:
        return "CORS_MISCONFIG"

    return c or t[:30]


def extract_url_endpoint(raw_url: str) -> str:
    """
    Extract normalized netloc and path from URL, discarding ephemeral query parameters.
    Preserves exact port and path to distinguish separate affected resources.
    Normalizes loopback host aliases (127.0.0.1 -> localhost) on the same port.
    """
    if not raw_url:
        return "/"
    try:
        parsed = urllib.parse.urlparse(raw_url)
        port_suffix = f":{parsed.port}" if parsed.port is not None else ""
        hostname = (parsed.hostname or "").lower()
        if hostname in ["127.0.0.1", "host.docker.internal"]:
            hostname = "localhost"
        netloc = f"{hostname}{port_suffix}"
        path = parsed.path.rstrip("/") or "/"
        return f"{netloc}{path}"
    except Exception:
        return raw_url.lower()


def compute_correlation_key(finding: Dict[str, Any]) -> str:
    """
    Compute fingerprint combining normalized endpoint, HTTP method, vulnerability category, and parameter.
    Ensures findings on different paths, ports, or parameters are never improperly merged.
    """
    asset = finding.get("affected_asset", {})
    url = str(asset.get("url") or finding.get("url") or "")
    endpoint = extract_url_endpoint(url)
    method = str(asset.get("method") or finding.get("method") or "GET").strip().upper()
    cwe = str(finding.get("cwe_id", ""))
    title = str(finding.get("title", ""))
    cat = normalize_vuln_category(title, cwe)
    param = str(asset.get("parameter") or finding.get("parameter") or "").strip().lower()

    return f"{endpoint}::{method}::{cat}::{param}"


def deduplicate_multi_scanner_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Merges duplicate detections across scanners.
    Preserves raw evidence from all detectors and tags corroborated alerts.
    """
    grouped = defaultdict(list)
    for f in findings:
        key = compute_correlation_key(f)
        grouped[key].append(f)

    deduped: List[Dict[str, Any]] = []
    raw_count = len(findings)
    corroborated_count = 0
    zap_unique = 0
    nuclei_unique = 0

    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}

    for key, group in grouped.items():
        if len(group) == 1:
            item = group[0]
            item["scanners_detected"] = [item.get("source_tool", "Unknown")]
            item["is_corroborated"] = False
            deduped.append(item)
            tool = item.get("source_tool", "")
            if "ZAP" in tool:
                zap_unique += 1
            else:
                nuclei_unique += 1
            continue

        # Multi-detection: select primary finding with highest severity and richest evidence
        corroborated_count += 1
        group.sort(
            key=lambda x: (
                severity_order.get(x.get("risk_rating", "Informational"), 0),
                len(str(x.get("evidence", {}).get("attack", ""))),
            ),
            reverse=True,
        )

        primary = group[0]
        detectors = list(set(g.get("source_tool", "Unknown") for g in group))
        primary["scanners_detected"] = detectors
        primary["is_corroborated"] = True

        # Aggregate secondary findings under provenance
        secondary_records = []
        for sec in group[1:]:
            sec_asset = sec.get("affected_asset", {})
            secondary_records.append({
                "source": sec.get("source") or sec.get("source_tool"),
                "source_tool": sec.get("source_tool") or sec.get("source"),
                "id": sec.get("id") or sec.get("finding_id"),
                "title": sec.get("title"),
                "risk_rating": sec.get("risk_rating") or sec.get("severity"),
                "url": sec_asset.get("url") or sec.get("url"),
                "method": sec_asset.get("method") or sec.get("method"),
                "parameter": sec_asset.get("parameter") or sec.get("parameter"),
                "evidence": sec.get("evidence"),
                "provenance": sec.get("provenance"),
            })
        primary.setdefault("provenance", {})["corroborating_findings"] = secondary_records

        deduped.append(primary)

    stats = {
        "raw_total": raw_count,
        "deduplicated_total": len(deduped),
        "reduction_count": raw_count - len(deduped),
        "corroborated_count": corroborated_count,
        "zap_unique": zap_unique,
        "nuclei_unique": nuclei_unique,
    }

    return deduped, stats
