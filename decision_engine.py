#!/usr/bin/env python3
"""
Project Zero-Day - Stage 1: Decision & Prioritization Engine
Script: decision_engine.py
Objective: Ingest normalized findings, group into unique alert categories,
           and assign operational priorities (P1-P4).
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from policy_model import get_policy_model
except ImportError:
    get_policy_model = None



def resolve_file_path(filename: str, search_dirs: Optional[List[Path]] = None) -> Path:
    """
    Dynamically resolve target file path across standard search locations.
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

    return Path(__file__).resolve().parent / filename


def categorize_alert(finding: Dict[str, Any]) -> str:
    """
    Determine standardized alert category based on CWE ID, title, and attack characteristics.
    """
    cwe_id = str(finding.get("cwe_id", "") or "").upper()
    title = str(finding.get("title", "") or "").lower()

    if "CWE-89" in cwe_id or "sql injection" in title or "sqli" in title:
        return "Injection Flaws"
    if "CWE-79" in cwe_id or "cross site scripting" in title or "xss" in title:
        return "Cross-Site Scripting (XSS)"
    if "CWE-1021" in cwe_id or "x-frame-options" in title or "clickjacking" in title:
        return "Clickjacking / UI Redressing"
    if "CWE-693" in cwe_id or "content security policy" in title or "csp" in title:
        return "Security Misconfiguration"
    if "CWE-1275" in cwe_id or "samesite" in title or "cookie" in title or "httponly" in title:
        return "Session Management / Cookie Security"

    # Default fallback to finding title
    return finding.get("title") or "Unclassified Web Alert"


def assign_priority(
    risk_rating: Optional[str],
    category: str,
    cwe_id: Optional[str],
    cvss_score: Optional[float] = None,
) -> str:
    """
    Authoritative Operational Triage Priority Mapping (P1-P4).

    Documented Mapping Rules:
    - P1 (Critical): Direct code execution, data compromise, severe injection flaws
                     (Scanner 'Critical', CWE-89 SQLi, CWE-78 OS Command, CWE-94 RCE, CVSS >= 9.0).
    - P2 (High): High-impact client-side or exploitable flaws
                 (Scanner 'High', CWE-79 XSS, CVSS 7.0-8.9).
    - P3 (Medium): Defense-in-depth gaps, clickjacking, CSRF, sensitive disclosure
                   (Scanner 'Medium', CWE-1021 UI Redressing, CWE-352 CSRF, CVSS 4.0-6.9).
    - P4 (Low/Info): Hardening recommendations, missing headers, cookie security flags, informational alerts
                     (Scanner 'Low', 'Informational', CVSS 0.1-3.9).

    Handling Missing, Malformed, or Unknown Severities:
    - If severity is missing/unknown but CWE indicates high risk (e.g. CWE-89), CWE takes precedence (P1/P2).
    - Otherwise, unclassified or malformed severities are explicitly triaged as P4 per documented policy:
      'Unclassified findings without corroborated high-risk CWE indicators are assigned P4 pending engineer review.'

    Authority Invariant:
    - Gemma AI advisory text is strictly non-authoritative and CANNOT override this calculated priority.
    - Original scanner severity is preserved separately in finding['risk_rating'].
    """
    risk_upper = str(risk_rating or "").strip().upper()
    cwe_str = str(cwe_id or "").strip().upper()

    # 1. CVSS score overrides if explicitly provided
    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if score >= 9.0:
                return "P1"
            elif score >= 7.0:
                return "P2"
            elif score >= 4.0:
                return "P3"
            elif score > 0.0:
                return "P4"
        except (ValueError, TypeError):
            pass

    # 2. Critical Flaws / Injections -> P1
    if (
        risk_upper == "CRITICAL"
        or "CWE-89" in cwe_str
        or "CWE-78" in cwe_str
        or "CWE-94" in cwe_str
        or category == "Injection Flaws"
    ):
        return "P1"

    # 3. High Risk / Client-Side Exploitation -> P2
    if (
        risk_upper == "HIGH"
        or "CWE-79" in cwe_str
        or category == "Cross-Site Scripting (XSS)"
    ):
        return "P2"

    # 4. Medium Risk / Defense-in-depth / UI Redressing -> P3
    if (
        risk_upper == "MEDIUM"
        or "CWE-1021" in cwe_str
        or "CWE-352" in cwe_str
        or category == "Clickjacking / UI Redressing"
    ):
        return "P3"

    # 5. Low / Informational / Hardening -> P4
    if risk_upper in ["LOW", "INFORMATIONAL", "INFO"]:
        return "P4"

    # 6. Fallback for unclassified / unknown / malformed
    # Explicitly documented triage to P4 unless high-risk indicator was matched above
    return "P4"


VALID_ACTIONS = (
    "collect_more_evidence",
    "inspect_related_endpoint",
    "verify_finding",
    "recommend_remediation",
    "manual_review",
)


def determine_heuristic_action(
    vulnerability_class: str,
    risk_rating: str,
    evidence: Optional[Dict[str, Any]] = None,
    priority: Optional[str] = None,
) -> str:
    """
    FR-02: Deterministic baseline heuristic rule mapping vulnerability_class,
    risk_rating, and evidence to an action from the finite allowlist:
    ('collect_more_evidence', 'inspect_related_endpoint', 'verify_finding',
     'recommend_remediation', 'manual_review').
    """
    v_class = str(vulnerability_class or "").lower()
    risk = str(risk_rating or "").upper()
    priority_str = str(priority or "").upper()
    evidence = evidence or {}

    attack = str(evidence.get("attack", "") or "").strip()
    evidence_str = str(evidence.get("evidence", "") or "").strip()
    has_concrete_evidence = bool(attack or evidence_str)

    # 1. High/Critical injection or severe exploits with concrete evidence -> verify_finding
    if risk in ["CRITICAL", "HIGH"] or priority_str in ["P1", "P2"]:
        if "injection" in v_class or "sqli" in v_class or "xss" in v_class:
            if has_concrete_evidence:
                return "verify_finding"
            return "collect_more_evidence"
        if has_concrete_evidence:
            return "verify_finding"
        return "collect_more_evidence"

    # 2. Medium risk / UI redressing / clickjacking -> inspect_related_endpoint
    if risk == "MEDIUM" or priority_str == "P3" or "clickjacking" in v_class or "frame" in v_class:
        return "inspect_related_endpoint"

    # 3. Low / Informational hardening / missing headers / cookie flags -> recommend_remediation
    if (
        risk in ["LOW", "INFORMATIONAL"]
        or priority_str == "P4"
        or "csp" in v_class
        or "cookie" in v_class
        or "samesite" in v_class
        or "misconfiguration" in v_class
    ):
        return "recommend_remediation"

    # 4. Fallback for unclassified / edge cases
    return "manual_review"


def run_decision_engine(input_path: Path, output_path: Path) -> List[Dict[str, Any]]:
    """
    FR-04: Groups normalized findings into unique alert categories and assigns priorities (P1-P4).
    FR-02: Assigns tactical heuristic action suggestions from finite allowlist.
    Guarantees that backup files (e.g. prioritized_findings_backup.json) remain untouched.
    """
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Safety Guard: Ensure we never overwrite backup files
    if "backup" in output_path.name.lower():
        raise ValueError("Safety guard triggered: refusing to write to backup file destination.")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Support either a list of findings or a dictionary containing 'findings'
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings", [])
    else:
        raise ValueError(f"Unexpected JSON data format in {input_path}: expected list or dict.")

    policy_model = get_policy_model() if get_policy_model else None
    model_name = "Decision Policy Model (36K Scenarios)" if (policy_model and policy_model.is_loaded) else "Deterministic Heuristics"

    grouped_alerts = defaultdict(list)
    priority_counter: Counter = Counter()
    action_counter: Counter = Counter()
    prioritized_findings: List[Dict[str, Any]] = []

    for finding in findings:
        category = categorize_alert(finding)
        priority = assign_priority(
            risk_rating=finding.get("risk_rating", "Informational"),
            category=category,
            cwe_id=finding.get("cwe_id"),
        )
        heuristic_action = determine_heuristic_action(
            vulnerability_class=category,
            risk_rating=finding.get("risk_rating", "Informational"),
            evidence=finding.get("evidence", {}),
            priority=priority,
        )

        # Predict tactical action using Decision Policy Model with defensive rule layer
        if policy_model and policy_model.is_loaded:
            action = policy_model.predict_action(
                finding=finding,
                fallback_action=heuristic_action,
            )
            if action not in VALID_ACTIONS:
                action = heuristic_action
        else:
            action = heuristic_action

        finding["priority"] = priority
        finding["alert_category"] = category
        finding["suggested_action"] = action
        finding["action"] = action

        grouped_alerts[category].append(finding["id"])
        priority_counter[priority] += 1
        action_counter[action] += 1
        prioritized_findings.append(finding)

    # Write prioritized findings output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(prioritized_findings, f, indent=2)

    # UI/UX Logging
    print("============================================================")
    print("Project Zero-Day: Decision Engine (Prioritization & Grouping)")
    print("============================================================")
    print(f"Action Selection Engine:     {model_name}")
    print(f"Input file:                  {input_path}")
    print(f"Total findings loaded:       {len(findings)}")
    print(f"Grouped alert categories:    {len(grouped_alerts)}")
    for cat, members in grouped_alerts.items():
        sample_priority = next((f["priority"] for f in prioritized_findings if f["alert_category"] == cat), "P4")
        print(f"  - {cat} ({sample_priority}): {len(members)} instance(s)")
    print("Priority distribution:")
    for prio in ["P1", "P2", "P3", "P4"]:
        print(f"  - {prio}: {priority_counter[prio]}")
    print("Suggested action distribution:")
    for act in VALID_ACTIONS:
        if action_counter[act] > 0:
            print(f"  - {act}: {action_counter[act]}")
    print(f"Output written to:           {output_path}")
    print("Status:                      SUCCESS")
    print("============================================================")

    return prioritized_findings


def main() -> None:
    input_arg = sys.argv[1] if len(sys.argv) > 1 else "normalized_findings.json"
    input_file = resolve_file_path(input_arg)
    output_file = input_file.parent / "prioritized_findings.json"

    try:
        results = run_decision_engine(input_file, output_file)
        if len(results) == 0:
            print("[WARN] Prioritized findings count is 0.", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Decision engine failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
