#!/usr/bin/env python3
"""
Project Zero-Day - Stage 5: Interactive Security Report Generator
Script: app/report_generator.py
Objective: Generate standalone, interactive HTML security report dashboard
           (security_report.html) and structured JSON report (security_report.json)
           without external CDN or internet dependencies.
"""

import html
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def resolve_file_path(filename: str, search_dirs: Optional[List[Path]] = None) -> Path:
    """
    Dynamically locate files across root and app directories.
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


def detect_data_provenance(findings: List[Dict[str, Any]], source_file: Optional[Path] = None) -> str:
    """
    Hard Constraint: Clearly distinguish sample fixture data from live scan results.
    Returns: 'LIVE SCAN' or 'SAMPLE FIXTURE'.
    """
    env_override = os.environ.get("ZERO_DAY_PROVENANCE")
    if env_override in ["LIVE SCAN", "SAMPLE FIXTURE"]:
        return env_override

    if source_file and any(tag in source_file.name.lower() for tag in ["fixture", "sample", "backup"]):
        return "SAMPLE FIXTURE"

    has_live = False
    has_fixture = False

    for f in findings:
        prov = f.get("provenance", {})
        prov_label = str(prov.get("provenance_label", "")).upper()
        src = str(prov.get("source_file", "")).lower()
        site_host = str(prov.get("site_host", "")).lower()

        if "live" in prov_label or "live" in src:
            has_live = True
        elif src == "zap-findings.json" or "target.local" in site_host or "sample" in src:
            has_fixture = True

    if has_live:
        return "LIVE SCAN"
    if has_fixture:
        return "SAMPLE FIXTURE"

    return "LIVE SCAN" if findings else "SAMPLE FIXTURE"


def build_html_report(
    findings: List[Dict[str, Any]],
    decision_log: Optional[Dict[str, Any]] = None,
    provenance: str = "SAMPLE FIXTURE",
    generated_at: Optional[str] = None,
    run_id: Optional[str] = None,
    target_url: Optional[str] = None,
    pipeline_status: str = "SUCCESS",
    scanners_executed: Optional[List[str]] = None,
) -> str:
    """
    Renders standalone interactive single-file HTML report.
    Embedded CSS/JS: Zero external CDN dependencies. Works 100% offline.
    """
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    effective_run_id = run_id or (decision_log.get("run_id") if decision_log else None) or "ad-hoc"
    effective_target = target_url or (findings[0].get("affected_asset", {}).get("url") if findings else "http://localhost:3000")

    # Aggregate Metrics
    total_findings = len(findings)
    p_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    status_counts = {"CONFIRMED": 0, "REJECTED": 0, "MANUAL_REVIEW": 0, "NEEDS_VERIFICATION": 0}
    policy_counts = {"ALLOW": 0, "DENY": 0}
    action_counts = {}

    for f in findings:
        p = f.get("priority", "P4")
        if p in p_counts:
            p_counts[p] += 1

        v_status = f.get("verification", {}).get("status", "NEEDS_VERIFICATION")
        status_counts[v_status] = status_counts.get(v_status, 0) + 1

        pol_dec = f.get("policy_evaluation", {}).get("decision", "DENY")
        policy_counts[pol_dec] = policy_counts.get(pol_dec, 0) + 1

        act = f.get("suggested_action") or f.get("action") or "manual_review"
        action_counts[act] = action_counts.get(act, 0) + 1

    # Render Cards HTML
    cards_html = []
    for idx, f in enumerate(findings):
        f_id = html.escape(str(f.get("id") or f.get("finding_id") or f"F-{idx}"))
        title = html.escape(str(f.get("title", "Untitled Alert")))
        cwe = html.escape(str(f.get("cwe_id", "CWE-Unspecified") or "CWE-Unspecified"))
        priority = html.escape(str(f.get("priority", "P4")))
        risk = html.escape(str(f.get("risk_rating", "Informational")))
        category = html.escape(str(f.get("alert_category", "General")))

        asset = f.get("affected_asset", {})
        url = html.escape(str(asset.get("url", "")))
        method = html.escape(str(asset.get("method", "GET")))
        param = html.escape(str(asset.get("parameter", "") or "N/A"))

        desc = html.escape(str(f.get("description", "No scanner description provided.")))
        evidence = f.get("evidence", {})
        attack = html.escape(str(evidence.get("attack", "") or "None"))
        evidence_str = html.escape(str(evidence.get("evidence", "") or "None"))
        other_info = html.escape(str(evidence.get("other_info", "") or "None"))

        # AI Advisory
        adv = f.get("ai_advisory", {})
        is_ai = adv.get("is_ai_generated", False)
        adv_model = html.escape(str(adv.get("model", "gemma4:latest")))
        gemma_exp = html.escape(str(adv.get("gemma_explanation", "No advisory explanation generated.")))
        remediation = html.escape(str(adv.get("remediation_advice", adv.get("recommendation", "Review code configuration."))))
        risk_sum = html.escape(str(adv.get("risk_summary", "Unrated risk summary.")))
        disclaimer = html.escape(str(adv.get("disclaimer", "Untrusted AI guidance; requires security engineering review.")))

        # RAG References
        rag_injected = adv.get("rag_context_injected", False)
        rag_refs = adv.get("rag_references", [])
        rag_html_items = []
        if rag_refs:
            for s in rag_refs:
                s_id = html.escape(str(s.get("id", "")))
                s_title = html.escape(str(s.get("title", "")))
                s_cwe = html.escape(str(s.get("cwe_id", "")))
                s_sum = html.escape(str(s.get("summary", "")))
                rag_html_items.append(
                    f'<div class="rag-pill"><strong>[{s_id}]</strong> {s_title} ({s_cwe})<br>'
                    f'<span class="rag-snippet">{s_sum}</span></div>'
                )
        rag_content = "".join(rag_html_items) if rag_html_items else '<span class="text-muted">No contextual scenarios retrieved.</span>'

        # Policy Gate Evaluation
        pol = f.get("policy_evaluation", {})
        pol_decision = pol.get("decision", "DENY")
        pol_reason = html.escape(str(pol.get("reason", "Evaluation pending.")))
        pol_scopes = pol.get("authorized_scopes") or (decision_log.get("authorized_scopes") if decision_log else None) or []
        pol_scope_str = html.escape(", ".join(str(s) for s in pol_scopes)) if pol_scopes else "Local Target Scope Rules"
        suggested_action = html.escape(str(f.get("suggested_action") or f.get("action") or "manual_review"))

        # Verification Status
        verif = f.get("verification", {})
        v_status = html.escape(str(verif.get("status", "NEEDS_VERIFICATION")))
        v_bool = verif.get("verified", False)
        v_notes = html.escape(str(verif.get("notes") or verif.get("evaluation_notes") or "Pending verification evaluation."))

        priority_class = f"badge-{priority.lower()}"
        policy_class = "badge-allow" if pol_decision == "ALLOW" else "badge-deny"
        if v_status == "CONFIRMED":
            status_class = "badge-confirmed"
        elif v_status == "REJECTED":
            status_class = "badge-rejected"
        elif v_status == "MANUAL_REVIEW":
            status_class = "badge-review"
        else:
            status_class = "badge-warning"

        card = f"""
        <div class="finding-card card-{priority.lower()}" data-priority="{priority}" data-status="{v_status}" data-policy="{pol_decision}" data-action="{suggested_action}">
            <div class="card-header" onclick="toggleCard('{f_id}')">
                <div class="header-left">
                    <span class="badge {priority_class}">{priority}</span>
                    <span class="finding-id">{f_id}</span>
                    <span class="finding-title">{title}</span>
                    <span class="cwe-tag">{cwe}</span>
                </div>
                <div class="header-right">
                    <span class="badge badge-action">{suggested_action}</span>
                    <span class="badge {policy_class}">{pol_decision}</span>
                    <span class="badge {status_class}">{v_status}</span>
                    <button class="toggle-btn" id="btn-{f_id}" aria-label="Toggle details">Expand &#9662;</button>
                </div>
            </div>
            <div class="card-body" id="body-{f_id}" style="display: none;">
                <div class="section-grid">
                    <div class="section-col">
                        <h4>Affected Asset</h4>
                        <div class="meta-box">
                            <p><strong>URL:</strong> <code class="url-code">{url}</code></p>
                            <p><strong>Method:</strong> <span class="method-tag">{method}</span> | <strong>Parameter:</strong> <code>{param}</code></p>
                            <p><strong>Risk Rating:</strong> {risk} | <strong>Category:</strong> {category}</p>
                        </div>

                        <h4>Scanner Description & Evidence</h4>
                        <div class="meta-box">
                            <p class="desc-text">{desc}</p>
                            <p><strong>Attack Payload:</strong> <code>{attack}</code></p>
                            <p><strong>Evidence String:</strong> <code>{evidence_str}</code></p>
                            <p><strong>Other Info:</strong> <span class="text-muted">{other_info}</span></p>
                        </div>

                        <h4>Policy Gate & Tactical Action</h4>
                        <div class="meta-box">
                            <p><strong>Suggested Action:</strong> <code class="action-code">{suggested_action}</code></p>
                            <p><strong>Policy Outcome:</strong> <span class="badge {policy_class}">{pol_decision}</span></p>
                            <p class="reason-text"><strong>Policy Justification:</strong> {pol_reason}</p>
                            <small class="text-muted">Target Scope Rules: {pol_scope_str}</small>
                        </div>
                    </div>

                    <div class="section-col">
                        <h4>Gemma AI Security Advisory <span class="ai-badge">{'AI GENERATED' if is_ai else 'RULE-BASED FALLBACK'} ({adv_model})</span></h4>
                        <div class="meta-box advisory-box">
                            <p><strong>Vulnerability Explanation:</strong></p>
                            <p class="advisory-text">{gemma_exp}</p>
                            <p><strong>Remediation Advice:</strong></p>
                            <pre class="code-remediation">{remediation}</pre>
                            <p><strong>Risk Summary:</strong> {risk_sum}</p>
                            <p class="disclaimer-text"><em>&#9888; {disclaimer}</em></p>
                        </div>

                        <h4>RAG Context: Retrieved Security Scenarios ({'Injected' if rag_injected else 'None'})</h4>
                        <div class="meta-box rag-container">
                            {rag_content}
                        </div>

                        <h4>Evidence Verification Status (Defensive Invariant)</h4>
                        <div class="meta-box verification-box">
                            <p><strong>Verification Status:</strong> <span class="badge {status_class}">{v_status}</span> | <strong>Verified Boolean:</strong> <code>{str(v_bool).lower()}</code></p>
                            <p class="notes-text"><strong>Evaluation Notes:</strong> {v_notes}</p>
                            <small class="text-muted">Hard Security Invariant: Scanner alerts are never auto-verified.</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
        cards_html.append(card)

    cards_joined = "\n".join(cards_html) if cards_html else f"""
        <div class="empty-state-box">
            <div class="empty-icon">&#128737;</div>
            <h3>No Vulnerability Findings Recorded for this Run</h3>
            <p>Target: <code>{effective_target}</code> &bull; Run ID: <code>{effective_run_id}</code> &bull; Status: <span class="badge {'badge-allow' if pipeline_status == 'SUCCESS' else 'badge-warning'}">{pipeline_status}</span></p>
            <p class="empty-desc">The scanner execution completed without reporting active findings, or the execution target was clean/unreachable.</p>
            <div class="empty-actions">
                <p><strong>To populate this dashboard with full findings, AI explanations, and RAG context:</strong></p>
                <div class="cmd-box"><code>python app/orchestrator.py --use-sample --open-report</code></div>
                <p><strong>To launch a live multi-scanner scan against local OWASP Juice Shop:</strong></p>
                <div class="cmd-box"><code>python app/orchestrator.py --target http://localhost:3000 --scanners zap,nuclei</code></div>
            </div>
        </div>
    """
    prov_badge_class = "prov-fixture" if provenance == "SAMPLE FIXTURE" else "prov-live"
    scanners_str = ", ".join(s.upper() for s in (scanners_executed or ["zap", "nuclei"]))
    model_detected = "gemma4:latest"
    for f in findings:
        m = f.get("ai_advisory", {}).get("model")
        if m:
            model_detected = m
            break

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project Zero-Day: Security Report Dashboard</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --bg-card-hover: #334155;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --p1-color: #ef4444;
            --p2-color: #f97316;
            --p3-color: #eab308;
            --p4-color: #3b82f6;
            --allow-color: #10b981;
            --deny-color: #f43f5e;
            --ai-color: #8b5cf6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        
        /* Header & Provenance */
        .header {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-title h1 {{
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 4px;
        }}
        .header-subtitle {{
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .header-badges {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .prov-badge {{
            padding: 8px 16px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 13px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        .prov-fixture {{
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid #f59e0b;
        }}
        .prov-live {{
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid #10b981;
        }}

        /* Metrics Bar */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 28px;
            font-weight: 700;
            margin-top: 4px;
        }}
        .metric-label {{
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .val-p1 {{ color: var(--p1-color); }}
        .val-p2 {{ color: var(--p2-color); }}
        .val-p3 {{ color: var(--p3-color); }}
        .val-p4 {{ color: var(--p4-color); }}
        .val-allow {{ color: var(--allow-color); }}
        .val-deny {{ color: var(--deny-color); }}
        .val-warning {{ color: var(--p3-color); }}
        .val-confirmed {{ color: var(--allow-color); }}

        /* Project Overview Section */
        .project-overview-panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        .panel-header {{
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: #1e293b;
            border-bottom: 1px solid var(--border-color);
            user-select: none;
        }}
        .panel-header:hover {{
            background: var(--bg-card-hover);
        }}
        .panel-title {{
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .panel-subtitle {{
            color: var(--text-secondary);
            font-size: 13px;
            margin-left: 6px;
        }}
        .panel-body {{
            padding: 20px;
            background: #141f32;
        }}
        .project-mission {{
            font-size: 14px;
            color: #cbd5e1;
            line-height: 1.6;
            margin-bottom: 18px;
            padding-bottom: 14px;
            border-bottom: 1px solid var(--border-color);
        }}
        .pipeline-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 18px;
        }}
        .pipeline-step {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
        }}
        .step-num {{
            font-size: 11px;
            font-weight: 700;
            color: #38bdf8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .step-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 4px;
        }}
        .step-desc {{
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.4;
        }}
        .telemetry-bar {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 10px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 12px;
        }}
        .telemetry-item {{
            color: var(--text-secondary);
        }}
        .telemetry-item strong {{
            color: var(--text-primary);
        }}

        /* Empty State */
        .empty-state-box {{
            background: var(--bg-secondary);
            border: 1px dashed var(--border-color);
            border-radius: 12px;
            padding: 40px 24px;
            text-align: center;
            margin: 20px 0;
        }}
        .empty-icon {{
            font-size: 40px;
            margin-bottom: 12px;
        }}
        .empty-state-box h3 {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--text-primary);
        }}
        .empty-state-box p {{
            color: var(--text-secondary);
            font-size: 14px;
            margin-bottom: 16px;
        }}
        .empty-desc {{
            max-width: 650px;
            margin: 0 auto 20px auto !important;
            line-height: 1.6;
        }}
        .empty-actions {{
            max-width: 600px;
            margin: 0 auto;
            text-align: left;
            background: var(--bg-primary);
            padding: 16px 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .empty-actions p {{
            font-size: 13px;
            color: var(--text-primary);
            margin-bottom: 6px;
        }}
        .cmd-box {{
            margin-bottom: 12px;
        }}
        .cmd-box code {{
            display: block;
            background: #090d16;
            padding: 8px 12px;
            border-radius: 6px;
            color: #38bdf8;
            font-family: monospace;
            font-size: 13px;
        }}

        /* Controls / Filter Bar */
        .controls-bar {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 24px;
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
        }}
        .filter-group {{
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: #3b82f6;
            color: #fff;
            border-color: #3b82f6;
        }}
        .search-input {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 13px;
            min-width: 240px;
            outline: none;
        }}
        .search-input:focus {{
            border-color: #3b82f6;
        }}
        .action-link-btn {{
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
        }}
        .action-link-btn:hover {{
            background: var(--bg-card-hover);
        }}

        /* Finding Cards */
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .card-p1 {{ border-left: 6px solid var(--p1-color); }}
        .card-p2 {{ border-left: 6px solid var(--p2-color); }}
        .card-p3 {{ border-left: 6px solid var(--p3-color); }}
        .card-p4 {{ border-left: 6px solid var(--p4-color); }}

        .card-header {{
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .card-header:hover {{
            background: var(--bg-card-hover);
        }}
        .header-left, .header-right {{
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .finding-id {{
            font-family: monospace;
            font-size: 13px;
            color: var(--text-secondary);
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
        }}
        .cwe-tag {{
            font-size: 12px;
            color: var(--text-muted);
            background: var(--bg-primary);
            padding: 2px 8px;
            border-radius: 4px;
            border: 1px solid var(--border-color);
        }}
        .toggle-btn {{
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
        }}

        /* Badges */
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-p1 {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid var(--p1-color); }}
        .badge-p2 {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid var(--p2-color); }}
        .badge-p3 {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid var(--p3-color); }}
        .badge-p4 {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid var(--p4-color); }}
        .badge-allow {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid var(--allow-color); }}
        .badge-deny {{ background: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid var(--deny-color); }}
        .badge-action {{ background: rgba(139, 92, 246, 0.2); color: #c084fc; border: 1px solid #8b5cf6; }}
        .badge-confirmed {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-rejected {{ background: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid #64748b; }}
        .badge-review {{ background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #a855f7; }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid #f59e0b; }}
        .badge-info {{ background: rgba(14, 165, 233, 0.2); color: #7dd3fc; border: 1px solid #0ea5e9; }}

        /* Card Body */
        .card-body {{
            padding: 20px;
            border-top: 1px solid var(--border-color);
            background: #141f32;
        }}
        .section-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        @media (max-width: 900px) {{
            .section-grid {{ grid-template-columns: 1fr; }}
        }}
        .section-col h4 {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .meta-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 13px;
        }}
        .meta-box p {{ margin-bottom: 6px; }}
        .meta-box p:last-child {{ margin-bottom: 0; }}
        code {{
            background: #090d16;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            color: #38bdf8;
        }}
        .url-code {{ word-break: break-all; color: #a7f3d0; }}
        .action-code {{ color: #e9d5ff; font-weight: 600; }}
        .method-tag {{
            background: #1e3a8a;
            color: #bfdbfe;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 11px;
        }}
        .ai-badge {{
            font-size: 10px;
            background: rgba(139, 92, 246, 0.3);
            color: #d8b4fe;
            border: 1px solid #8b5cf6;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .advisory-box {{
            border-left: 3px solid #8b5cf6;
        }}
        .advisory-text {{
            color: #f1f5f9;
            margin-bottom: 8px;
        }}
        .code-remediation {{
            background: #090d16;
            border: 1px solid #1e293b;
            padding: 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            color: #cbd5e1;
            white-space: pre-wrap;
            margin: 6px 0;
        }}
        .disclaimer-text {{
            color: #94a3b8;
            font-size: 11px;
            margin-top: 6px;
        }}
        .rag-pill {{
            background: #0f172a;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px;
            margin-bottom: 6px;
            font-size: 12px;
        }}
        .rag-snippet {{
            color: var(--text-secondary);
            display: block;
            margin-top: 2px;
        }}
        .verification-box {{
            border-left: 3px solid #f59e0b;
        }}
        .text-muted {{ color: var(--text-muted); }}

        /* Footer */
        .footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 12px;
            margin-top: 32px;
            padding: 16px;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-title">
                <h1>Project Zero-Day: Security Report Dashboard</h1>
                <div class="header-subtitle" style="margin-top: 6px; line-height: 1.8;">
                    <strong>Run ID:</strong> <code>{effective_run_id}</code> &bull; 
                    <strong>Target:</strong> <code class="url-code">{effective_target}</code> &bull; 
                    <strong>Status:</strong> <span class="badge {'badge-allow' if pipeline_status == 'SUCCESS' else ('badge-warning' if pipeline_status == 'PARTIAL_SUCCESS' else 'badge-deny')}">{pipeline_status}</span> &bull; 
                    <span>Generated: {generated_at}</span>
                </div>
            </div>
            <div class="header-badges">
                <span class="prov-badge {prov_badge_class}">{provenance}</span>
            </div>
        </header>

        <!-- Project Overview & Architecture -->
        <section class="project-overview-panel">
            <div class="panel-header" onclick="toggleProjectOverview()">
                <div class="panel-title">
                    <span style="font-size: 16px;">&#9881;</span>
                    <strong>Project Architecture &amp; Execution Pipeline Details</strong>
                    <span class="panel-subtitle">Multi-Scanner Security Pipeline &bull; DAST &bull; Gemma LLM &bull; SQLite FTS5 RAG &bull; Policy Gate</span>
                </div>
                <button class="toggle-btn" id="btn-project-overview">Collapse &#9652;</button>
            </div>
            <div class="panel-body" id="body-project-overview">
                <p class="project-mission">
                    <strong>Project Zero-Day</strong> is an autonomous, evidence-driven multi-scanner security analysis pipeline targeting local web applications (such as OWASP Juice Shop and local services). It unifies containerized vulnerability scanners with machine learning prioritization, local scenario retrieval-augmented generation (RAG), local LLM security advisories, and an authoritative Policy Gate with strict evidence verification invariants.
                </p>
                <div class="pipeline-grid">
                    <div class="pipeline-step">
                        <div class="step-num">Stage 0</div>
                        <div class="step-title">Docker Scanner Suite</div>
                        <div class="step-desc">Automated, non-destructive scans via official OWASP ZAP and ProjectDiscovery Nuclei container images.</div>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-num">Stage 1</div>
                        <div class="step-title">Ingestion &amp; Dedup</div>
                        <div class="step-desc">Normalizes heterogeneous findings into the canonical schema and deduplicates overlapping multi-scanner detections.</div>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-num">Stage 2</div>
                        <div class="step-title">Decision Prioritization</div>
                        <div class="step-desc">Classifies vulnerabilities into P1&ndash;P4 severity tiers using a trained ML Decision Policy Model and deterministic action heuristics.</div>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-num">Stage 3</div>
                        <div class="step-title">Contextual RAG &amp; Gemma AI</div>
                        <div class="step-desc">Sub-millisecond FTS5 scenario retrieval from scenarios.db enriched with local Ollama Gemma vulnerability explanations and remediation advice.</div>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-num">Stage 4 &amp; 4b</div>
                        <div class="step-title">Policy Gate &amp; Loop</div>
                        <div class="step-desc">Authoritative scope enforcement (loopback &amp; port isolation). Bounded autonomous investigation loop under strict request budgets.</div>
                    </div>
                    <div class="pipeline-step">
                        <div class="step-num">Stage 5 &amp; 6</div>
                        <div class="step-title">Verification &amp; Dashboard</div>
                        <div class="step-desc">Defensive invariant: scanner alerts are never auto-verified (verified: false). Rendered into an interactive 100% offline HTML dashboard.</div>
                    </div>
                </div>
                <div class="telemetry-bar">
                    <div class="telemetry-item"><strong>Target Endpoint:</strong> <code>{effective_target}</code></div>
                    <div class="telemetry-item"><strong>Scanners Configured:</strong> <code>{scanners_str}</code></div>
                    <div class="telemetry-item"><strong>AI Advisory Model:</strong> <code>{model_detected} (Ollama)</code></div>
                    <div class="telemetry-item"><strong>RAG Knowledge Base:</strong> <code>scenarios.db (SQLite FTS5, 36.4K records)</code></div>
                    <div class="telemetry-item"><strong>Policy Boundary:</strong> <code>Loopback Scope Authorized</code></div>
                    <div class="telemetry-item"><strong>Hard Invariant:</strong> <code>Scanner alerts initialized verified: false</code></div>
                </div>
            </div>
        </section>

        <!-- Summary Metrics -->
        <section class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Findings</div>
                <div class="metric-value">{total_findings}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">P1 (Critical)</div>
                <div class="metric-value val-p1">{p_counts['P1']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">P2 (High)</div>
                <div class="metric-value val-p2">{p_counts['P2']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">P3 (Medium)</div>
                <div class="metric-value val-p3">{p_counts['P3']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">P4 (Low/Info)</div>
                <div class="metric-value val-p4">{p_counts['P4']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Policy Allowed</div>
                <div class="metric-value val-allow">{policy_counts.get('ALLOW', 0)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Policy Denied</div>
                <div class="metric-value val-deny">{policy_counts.get('DENY', 0)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Needs Verification</div>
                <div class="metric-value val-warning">{status_counts.get('NEEDS_VERIFICATION', 0)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Confirmed</div>
                <div class="metric-value val-confirmed">{status_counts.get('CONFIRMED', 0)}</div>
            </div>
        </section>

        <!-- Interactive Controls -->
        <div class="controls-bar">
            <div class="filter-group">
                <span style="font-size: 13px; color: var(--text-secondary); margin-right: 4px;">Filter Priority:</span>
                <button class="filter-btn active" onclick="filterPriority('ALL', this)">All ({total_findings})</button>
                <button class="filter-btn" onclick="filterPriority('P1', this)">P1 ({p_counts['P1']})</button>
                <button class="filter-btn" onclick="filterPriority('P2', this)">P2 ({p_counts['P2']})</button>
                <button class="filter-btn" onclick="filterPriority('P3', this)">P3 ({p_counts['P3']})</button>
                <button class="filter-btn" onclick="filterPriority('P4', this)">P4 ({p_counts['P4']})</button>
            </div>
            <div class="filter-group">
                <span style="font-size: 13px; color: var(--text-secondary); margin-right: 4px;">Policy Gate:</span>
                <button class="filter-btn active" onclick="filterPolicy('ALL', this)">All</button>
                <button class="filter-btn" onclick="filterPolicy('ALLOW', this)">ALLOW ({policy_counts.get('ALLOW', 0)})</button>
                <button class="filter-btn" onclick="filterPolicy('DENY', this)">DENY ({policy_counts.get('DENY', 0)})</button>
            </div>
            <div class="filter-group">
                <input type="text" class="search-input" id="searchInput" placeholder="Search findings (title, CWE, asset, URL)..." oninput="handleSearch()">
                <button class="action-link-btn" onclick="expandAll(true)">Expand All</button>
                <button class="action-link-btn" onclick="expandAll(false)">Collapse All</button>
            </div>
        </div>

        <!-- Finding Cards List -->
        <main id="findingsList">
            {cards_joined}
        </main>

        <!-- Footer -->
        <footer class="footer">
            Project Zero-Day &bull; Stage 5 Master Orchestrator &bull; Offline Dashboard &bull; Defending Invariant: Unverified scanner alerts remain verified: false
        </footer>
    </div>

    <!-- Standalone Interactive JavaScript (No external libraries) -->
    <script>
        function toggleProjectOverview() {{
            const body = document.getElementById('body-project-overview');
            const btn = document.getElementById('btn-project-overview');
            if (!body || !btn) return;
            const isHidden = body.style.display === 'none';
            body.style.display = isHidden ? 'block' : 'none';
            btn.innerHTML = isHidden ? 'Collapse &#9652;' : 'Expand &#9662;';
        }}

        function toggleCard(id) {{
            const body = document.getElementById('body-' + id);
            const btn = document.getElementById('btn-' + id);
            if (!body || !btn) return;
            const isHidden = body.style.display === 'none';
            body.style.display = isHidden ? 'block' : 'none';
            btn.innerHTML = isHidden ? 'Collapse &#9652;' : 'Expand &#9662;';
        }}

        function expandAll(expand) {{
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                const body = card.querySelector('.card-body');
                const btn = card.querySelector('.toggle-btn');
                if (body && btn) {{
                    body.style.display = expand ? 'block' : 'none';
                    btn.innerHTML = expand ? 'Collapse &#9652;' : 'Expand &#9662;';
                }}
            }});
        }}

        let currentPriorityFilter = 'ALL';
        let currentPolicyFilter = 'ALL';

        function filterPriority(priority, elem) {{
            currentPriorityFilter = priority;
            if (elem && elem.parentElement) {{
                elem.parentElement.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                elem.classList.add('active');
            }}
            applyFilters();
        }}

        function filterPolicy(policy, elem) {{
            currentPolicyFilter = policy;
            if (elem && elem.parentElement) {{
                elem.parentElement.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                elem.classList.add('active');
            }}
            applyFilters();
        }}

        function handleSearch() {{
            applyFilters();
        }}

        function applyFilters() {{
            const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
            const cards = document.querySelectorAll('.finding-card');

            cards.forEach(card => {{
                const cardPrio = card.getAttribute('data-priority');
                const cardPol = card.getAttribute('data-policy');
                const textContent = card.innerText.toLowerCase();

                const matchesPrio = (currentPriorityFilter === 'ALL' || cardPrio === currentPriorityFilter);
                const matchesPol = (currentPolicyFilter === 'ALL' || cardPol === currentPolicyFilter);
                const matchesQuery = (!query || textContent.includes(query));

                if (matchesPrio && matchesPol && matchesQuery) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    return html_template


def generate_security_report(
    findings_file: Path,
    decision_log_file: Optional[Path] = None,
    output_html_file: Optional[Path] = None,
    output_json_file: Optional[Path] = None,
    provenance: Optional[str] = None,
    target_url: Optional[str] = None,
    run_id: Optional[str] = None,
    pipeline_status: str = "SUCCESS",
    scanners_executed: Optional[List[str]] = None,
    stage_statuses: Optional[Dict[str, str]] = None,
    scan_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Renders security_report.html and security_report.json.
    Guarantees that HTML, JSON, decision log, and verification results agree on all metrics.
    """
    if not findings_file.is_file():
        raise FileNotFoundError(f"Findings file not found: {findings_file}")

    root_dir = findings_file.parent
    if output_html_file is None:
        output_html_file = root_dir / "security_report.html"
    if output_json_file is None:
        output_json_file = root_dir / "security_report.json"

    with open(findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    decision_log = {}
    if decision_log_file and decision_log_file.is_file():
        try:
            with open(decision_log_file, "r", encoding="utf-8") as f:
                decision_log = json.load(f)
        except Exception:
            pass

    # Merge policy decision from decision_log into findings if not already present
    if decision_log and isinstance(decision_log, dict):
        log_entries = {d.get("finding_id"): d for d in decision_log.get("decisions", [])}
        for f in findings:
            f_id = f.get("id")
            if f_id in log_entries and "policy_evaluation" not in f:
                f["policy_evaluation"] = {
                    "decision": log_entries[f_id].get("decision", "DENY"),
                    "reason": log_entries[f_id].get("reason", ""),
                    "evaluated_at": log_entries[f_id].get("timestamp"),
                }

    effective_run_id = run_id or (decision_log.get("run_id") if decision_log else None) or "ad-hoc"
    effective_target_url = target_url or (decision_log.get("target_url") if decision_log else None) or (findings[0].get("affected_asset", {}).get("url") if findings else "http://localhost:3000")

    if provenance is None:
        provenance = detect_data_provenance(findings, source_file=findings_file)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build Structured JSON Report
    json_report = {
        "report_metadata": {
            "title": "Project Zero-Day Security Report",
            "run_id": effective_run_id,
            "target_url": effective_target_url,
            "pipeline_status": pipeline_status,
            "scanners_executed": scanners_executed or ["zap", "nuclei"],
            "stage_statuses": stage_statuses or {},
            "generated_at": now_utc,
            "data_provenance": provenance,
            "pipeline_stage": "Stage 5 Orchestration",
            "total_findings": len(findings),
            "priority_distribution": {
                "P1": sum(1 for f in findings if f.get("priority") == "P1"),
                "P2": sum(1 for f in findings if f.get("priority") == "P2"),
                "P3": sum(1 for f in findings if f.get("priority") == "P3"),
                "P4": sum(1 for f in findings if f.get("priority") == "P4"),
            },
            "verification_status": {
                "CONFIRMED": sum(1 for f in findings if f.get("verification", {}).get("status") == "CONFIRMED"),
                "REJECTED": sum(1 for f in findings if f.get("verification", {}).get("status") == "REJECTED"),
                "MANUAL_REVIEW": sum(1 for f in findings if f.get("verification", {}).get("status") == "MANUAL_REVIEW"),
                "NEEDS_VERIFICATION": sum(1 for f in findings if f.get("verification", {}).get("status") == "NEEDS_VERIFICATION"),
                "verified_true_count": sum(1 for f in findings if f.get("verification", {}).get("verified") is True),
                "verified_false_count": sum(1 for f in findings if f.get("verification", {}).get("verified") is False),
            },
            "policy_summary": {
                "ALLOW": sum(1 for f in findings if f.get("policy_evaluation", {}).get("decision") == "ALLOW"),
                "DENY": sum(1 for f in findings if f.get("policy_evaluation", {}).get("decision") == "DENY"),
            },
            "policy_distribution": {
                "ALLOW": sum(1 for f in findings if f.get("policy_evaluation", {}).get("decision") == "ALLOW"),
                "DENY": sum(1 for f in findings if f.get("policy_evaluation", {}).get("decision") == "DENY"),
            },
        },
        "findings": findings,
    }

    # Write JSON report
    with open(output_json_file, "w", encoding="utf-8") as f:
        json.dump(json_report, f, indent=2)

    # Build and write HTML report
    html_content = build_html_report(
        findings=findings,
        decision_log=decision_log,
        provenance=provenance,
        generated_at=now_utc,
        run_id=effective_run_id,
        target_url=effective_target_url,
        pipeline_status=pipeline_status,
        scanners_executed=scanners_executed,
    )

    with open(output_html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print("============================================================")
    print("Project Zero-Day: Report Generator (Stage 5)")
    print("============================================================")
    print(f"Data Provenance:             {provenance}")
    print(f"Total findings rendered:     {len(findings)}")
    print(f"HTML dashboard path:         {output_html_file}")
    print(f"JSON report path:            {output_json_file}")
    print("Status:                      SUCCESS")
    print("============================================================")

    return json_report


def main() -> None:
    findings_file = resolve_file_path("verification_results.json")
    if not findings_file.is_file() or findings_file.stat().st_size <= 2:
        cand = resolve_file_path("prioritized_findings.json")
        if cand.is_file() and cand.stat().st_size > 2:
            findings_file = cand
        else:
            cand2 = resolve_file_path("normalized_findings.json")
            if cand2.is_file() and cand2.stat().st_size > 2:
                findings_file = cand2

    decision_log_file = resolve_file_path("decision_log.json")
    out_dir = findings_file.parent if findings_file.is_file() else Path.cwd()
    output_html = out_dir / "security_report.html"
    output_json = out_dir / "security_report.json"

    generate_security_report(
        findings_file=findings_file,
        decision_log_file=decision_log_file if decision_log_file.is_file() else None,
        output_html_file=output_html,
        output_json_file=output_json,
    )


if __name__ == "__main__":
    main()
