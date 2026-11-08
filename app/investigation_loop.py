#!/usr/bin/env python3
"""
Project Zero-Day - Milestone 3: Bounded Autonomous Investigation Loop
Script: app/investigation_loop.py
Objective: Execute a bounded, multi-step defensive investigation loop driven by the
           trained Random Forest decision policy model (policy_model.joblib).
           Enforces strict constraints:
           - Bounded budget: Max 4 steps per finding, 50 total HTTP requests per run.
           - Rate limiting: Minimum 100ms between requests.
           - Authoritative Policy Gate: Loopback-only authorized scope enforcement.
           - State progression: initial_scan -> enumeration -> deep_analysis -> verification -> remediation_advisory.
           - Action allowlist: collect_more_evidence, inspect_related_endpoint, verify_finding,
                               recommend_remediation, manual_review.
           - Complete auditability: Every action, observation, decision, and confidence score logged.
"""

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from policy_model import DecisionPolicyModel, VALID_ACTIONS
from app.verification_engine import (
    verify_finding_evidence,
    _normalize_probe_url,
    _defensive_http_probe,
)


class InvestigationController:
    """
    Manages multi-step bounded investigations for findings using the Random Forest policy model.
    """

    def __init__(
        self,
        policy_gate: Any = None,
        model: Optional[DecisionPolicyModel] = None,
        max_steps_per_finding: int = 4,
        max_total_requests: int = 50,
        request_interval_sec: float = 0.1,
        target_url: str = "http://localhost:3000",
        is_live: bool = True,
    ):
        self.policy_gate = policy_gate
        self.model = model or DecisionPolicyModel()
        self.max_steps_per_finding = max_steps_per_finding
        self.max_total_requests = max_total_requests
        self.request_interval_sec = request_interval_sec
        self.target_url = target_url
        self.is_live = is_live

        # Telemetry counters
        self.total_requests_executed = 0
        self.total_steps_executed = 0

    def investigate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an iterative, bounded investigation trajectory for a single finding.
        Returns the enriched finding with an 'investigation_trajectory' block.
        """
        f_id = finding.get("id", "UNKNOWN")
        asset_url = finding.get("affected_asset", {}).get("url") or self.target_url
        probe_url = _normalize_probe_url(asset_url, default_target=self.target_url)

        # Policy Gate pre-check
        in_scope = True
        if self.policy_gate is not None:
            in_scope = self.policy_gate.is_in_scope(probe_url)

        trajectory: List[Dict[str, Any]] = []
        current_phase = "initial_scan"
        prior_action = "none"
        prior_action_failed = False
        final_action = "manual_review"

        for step in range(1, self.max_steps_per_finding + 1):
            if self.total_requests_executed >= self.max_total_requests:
                trajectory.append({
                    "step": step,
                    "phase": current_phase,
                    "action": "budget_exhausted",
                    "confidence": 1.0,
                    "observation": f"Investigation halted: global request budget of {self.max_total_requests} reached.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                final_action = prior_action if prior_action in VALID_ACTIONS else "manual_review"
                break

            self.total_steps_executed += 1

            # 1. Predict next tactical action via Random Forest policy model
            action, confidence = self.model.predict_action_with_confidence(
                finding=finding,
                phase=current_phase,
                step_number=step,
                total_steps=self.max_steps_per_finding,
                prior_action=prior_action,
                prior_action_failed=prior_action_failed,
                fallback_action="manual_review",
            )

            step_record: Dict[str, Any] = {
                "step": step,
                "phase": current_phase,
                "action": action,
                "confidence": round(confidence, 4),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # 2. Defensive action execution
            observation = ""
            action_failed = False

            if not self.is_live or not in_scope:
                # Offline / sample fixture or out-of-scope invariant
                observation = (
                    f"Offline/Sample mode: Tactical action '{action}' selected by decision model "
                    f"(confidence {confidence:.2f}). Outbound probe skipped per policy."
                )
                if action in ["recommend_remediation", "manual_review"]:
                    step_record["observation"] = observation
                    trajectory.append(step_record)
                    final_action = action
                    break
                # Advance phase heuristically
                if current_phase == "initial_scan":
                    current_phase = "enumeration"
                elif current_phase == "enumeration":
                    current_phase = "deep_analysis"
                elif current_phase == "deep_analysis":
                    current_phase = "verification"
                else:
                    current_phase = "remediation_advisory"

                step_record["observation"] = observation
                trajectory.append(step_record)
                prior_action = action
                continue

            # --- LIVE INVESTIGATION EXECUTION ---
            time.sleep(self.request_interval_sec)

            if action == "collect_more_evidence":
                self.total_requests_executed += 1
                status_code, headers, snippet, _ = _defensive_http_probe(probe_url, method="HEAD", timeout=3.0)
                if status_code is not None:
                    observation = f"HTTP HEAD returned status {status_code}; observed {len(headers)} response headers."
                    finding.setdefault("evidence", {})["observed_headers_sample"] = list(headers.keys())
                    current_phase = "deep_analysis"
                else:
                    observation = f"Probe connection error: {snippet}"
                    action_failed = True

            elif action == "inspect_related_endpoint":
                self.total_requests_executed += 1
                # Check related endpoints defensively (e.g. root or swagger)
                related_url = self.target_url if probe_url != self.target_url else f"{self.target_url}/api-docs/swagger.json"
                status_code, headers, snippet, _ = _defensive_http_probe(related_url, method="GET", timeout=3.0)
                if status_code is not None:
                    observation = f"Related endpoint {related_url} returned HTTP {status_code}."
                    current_phase = "verification"
                else:
                    observation = f"Related endpoint inspection failed: {snippet}"
                    action_failed = True

            elif action == "verify_finding":
                # Execute genuine evidence verification
                self.total_requests_executed += 1
                verif_result = verify_finding_evidence(
                    finding,
                    target_base_url=self.target_url,
                    policy_gate=self.policy_gate,
                )
                finding["verification"] = verif_result
                v_status = verif_result.get("status", "NEEDS_VERIFICATION")
                observation = f"Evidence verification executed: outcome is {v_status} ({verif_result.get('evaluation_notes')})"
                current_phase = "remediation_advisory"

            elif action == "recommend_remediation":
                observation = "Remediation phase reached: finding enriched with defensive guidance and RAG context."
                step_record["observation"] = observation
                trajectory.append(step_record)
                final_action = action
                break

            elif action == "manual_review":
                observation = "Safety gate / policy model escalated finding to manual security review."
                step_record["observation"] = observation
                trajectory.append(step_record)
                final_action = action
                break

            else:
                observation = f"Unrecognized action '{action}'; falling back to manual review."
                final_action = "manual_review"
                step_record["observation"] = observation
                trajectory.append(step_record)
                break

            step_record["observation"] = observation
            trajectory.append(step_record)

            prior_action = action
            prior_action_failed = action_failed

            # If the model reaches the final phase or completes verification, conclude gracefully
            if current_phase == "remediation_advisory":
                final_action = "recommend_remediation"
                break

        finding["investigation_trajectory"] = {
            "total_steps": len(trajectory),
            "final_action": final_action,
            "trajectory": trajectory,
        }
        finding["suggested_action"] = final_action
        return finding

    def run_investigation_suite(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs bounded investigations across all findings in the pipeline.
        Returns a summary report dictionary with enriched findings and trajectory logs.
        """
        start_time = time.perf_counter()
        print(f"\n[*] Starting Bounded Investigation Loop ({'LIVE' if self.is_live else 'OFFLINE/SAMPLE'})...")
        print(f"[*] Total Findings:          {len(findings)}")
        print(f"[*] Step Budget Per Finding: {self.max_steps_per_finding}")
        print(f"[*] Global Request Budget:   {self.max_total_requests}")

        investigated_findings: List[Dict[str, Any]] = []
        action_distribution: Dict[str, int] = {a: 0 for a in VALID_ACTIONS}

        for idx, finding in enumerate(findings):
            investigated = self.investigate_finding(finding)
            investigated_findings.append(investigated)
            act = investigated.get("suggested_action", "manual_review")
            action_distribution[act] = action_distribution.get(act, 0) + 1

        elapsed = round(time.perf_counter() - start_time, 2)
        print(f"[+] Investigation Loop Completed in {elapsed}s:")
        print(f"    - Total Steps Executed:   {self.total_steps_executed}")
        print(f"    - HTTP Requests Made:     {self.total_requests_executed}")
        print("    - Final Action Breakdown:")
        for act, count in action_distribution.items():
            if count > 0:
                print(f"      * {act}: {count}")

        return {
            "findings": investigated_findings,
            "summary": {
                "total_findings": len(findings),
                "total_steps": self.total_steps_executed,
                "total_requests": self.total_requests_executed,
                "duration_seconds": elapsed,
                "action_distribution": action_distribution,
            },
        }
