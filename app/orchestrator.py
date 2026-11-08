#!/usr/bin/env python3
"""
Project Zero-Day - Stage 5: Master Pipeline Orchestrator
Script: app/orchestrator.py
Objective: Fully automated, evidence-driven multi-scanner security analysis pipeline
           targeting OWASP Juice Shop (or custom scope).
           - Stage 0: Automated Multi-Scanner Execution (ZAP + Nuclei in Docker)
           - Stage 1: Finding Normalization & Multi-Scanner Deduplication
           - Stage 2: Prioritization & Deterministic Action Heuristics (P1-P4, finite allowlist)
           - Stage 3: Scenario Dataset RAG (SQLite FTS5) & Ollama Gemma LLM Advisory
           - Stage 4: Authoritative Policy Gate (Loopback & Port Scope Enforcement)
           - Stage 5: Structured Evidence Verification (Defensive security invariants)
           - Stage 6: Standalone Interactive HTML/JSON Report Dashboard
"""

import argparse
import json
import os
import shutil
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root and app directory are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent
for p in [PROJECT_ROOT, APP_DIR]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

# Component imports
import normalize_findings
from decision_engine import determine_heuristic_action, run_decision_engine, VALID_ACTIONS
from app.gemma_advisory import GemmaAdvisoryClient, enrich_findings_file
from app.verification_engine import run_verification_engine, evaluate_finding_verification
from app.report_generator import generate_security_report, detect_data_provenance
from app.scanner_manager import run_multi_scanner_suite, ensure_juice_shop_container, check_docker_daemon
from app.nuclei_normalizer import normalize_nuclei_findings
from app.finding_deduplicator import deduplicate_multi_scanner_findings
from app.investigation_loop import InvestigationController
from app.target_validator import (
    is_loopback_host,
    parse_and_validate_target,
    map_to_container_target,
    verify_target_reachability,
    TargetValidationError,
    TargetUnreachableError,
    BlockedRedirectError,
    DockerConnectivityError,
)


class PolicyGate:
    """
    Authoritative Policy Gate enforcing target scope constraints.
    Hard Constraint: AI explanations and heuristic action selections are strictly advisory;
    the Policy Gate retains absolute authority over execution.
    """

    LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}

    def __init__(
        self,
        authorized_scopes: Optional[List[str]] = None,
        allow_arbitrary_loopback_ports: bool = False,
    ):
        has_wildcard_scope = False
        if authorized_scopes:
            for s in authorized_scopes:
                s_str = str(s).strip().lower()
                if (
                    "*" in s_str
                    or s_str == "local"
                    or (s_str.startswith("http://localhost") and ":" not in s_str.replace("http://", ""))
                    or (s_str.startswith("http://127.0.0.1") and ":" not in s_str.replace("http://", ""))
                    or (s_str.startswith("localhost") and ":" not in s_str)
                    or (s_str.startswith("127.0.0.1") and ":" not in s_str)
                ):
                    has_wildcard_scope = True
                    break

        if authorized_scopes is None:
            # Reusable local-target authorization policy:
            # Default to allowing loopback on arbitrary valid ports
            self.allow_arbitrary_loopback_ports = True
            raw_scopes = ["http://localhost:*", "http://127.0.0.1:*"]
        else:
            self.allow_arbitrary_loopback_ports = allow_arbitrary_loopback_ports or has_wildcard_scope
            raw_scopes = authorized_scopes

        self.authorized_scopes = raw_scopes
        self.rules = [self._parse_scope_rule(s) for s in raw_scopes if s]

    @classmethod
    def create_local_target_policy(cls) -> "PolicyGate":
        """
        Factory method creating a reusable local-target authorization policy.
        Permits loopback targets across arbitrary valid ports while strictly
        enforcing boundaries against remote and untrusted targets.
        """
        return cls(
            authorized_scopes=["http://localhost:*", "http://127.0.0.1:*"],
            allow_arbitrary_loopback_ports=True,
        )

    @classmethod
    def _parse_scope_rule(cls, scope_str: str) -> Dict[str, Any]:
        raw = scope_str.strip().lower()
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        has_port_wildcard = ":*" in raw or raw.endswith(":*")
        if has_port_wildcard:
            raw = raw.replace(":*", "")
        parsed = urllib.parse.urlparse(raw)
        host = (parsed.hostname or "").lower()
        port = None if has_port_wildcard else parsed.port
        if port is None and not has_port_wildcard:
            port = 443 if parsed.scheme == "https" else 80
        is_loopback = is_loopback_host(host) or host in cls.LOOPBACK_HOSTS
        return {
            "raw": scope_str,
            "scheme": parsed.scheme,
            "host": host,
            "port": port,
            "has_port_wildcard": has_port_wildcard,
            "is_loopback": is_loopback,
        }

    def is_in_scope(self, url: str) -> bool:
        allowed, _ = self.check_scope_detailed(url)
        return allowed

    def check_scope_detailed(self, url: str) -> Tuple[bool, str]:
        if not url or not isinstance(url, str):
            return False, "Target URL is empty or missing."

        clean_url = url.strip()

        # Anti-bypass: Prohibit userinfo (@) syntax
        if "@" in clean_url:
            return False, f"Target URL '{clean_url}' rejected: userinfo (@) syntax prohibited."

        parsed = urllib.parse.urlparse(clean_url)

        if parsed.scheme.lower() not in ["http", "https"]:
            return False, f"Target scheme '{parsed.scheme}' rejected: only HTTP and HTTPS allowed."

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, "Target URL missing valid hostname."

        try:
            port = parsed.port
        except ValueError:
            return False, f"Target URL '{clean_url}' rejected: invalid port number."
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80

        target_is_loopback = is_loopback_host(hostname) or (hostname in self.LOOPBACK_HOSTS)

        # 1. Arbitrary loopback port policy (reusable local-target policy)
        if self.allow_arbitrary_loopback_ports:
            if target_is_loopback:
                if 1 <= port <= 65535:
                    return True, (
                        f"Target URL '{clean_url}' is within authorized scope '{self.authorized_scopes[0] if self.authorized_scopes else 'local'}' "
                        f"(loopback alias '{hostname}', port {port})."
                    )
                else:
                    return False, f"Target URL '{clean_url}' port {port} rejected: invalid port number."
            # If not loopback, check if any non-loopback rule matches
            for rule in self.rules:
                if not rule["is_loopback"] and hostname == rule["host"]:
                    if rule["has_port_wildcard"] or port == rule["port"]:
                        return True, f"Target URL '{clean_url}' matches authorized scope '{rule['raw']}'."
            return False, (
                f"Target URL '{clean_url}' host '{hostname}' is outside authorized scope "
                f"({self.authorized_scopes[0] if self.authorized_scopes else 'local'})."
            )

        # 2. Strict / explicit scope rule matching
        for rule in self.rules:
            # Scheme match
            if rule["scheme"] and parsed.scheme.lower() != rule["scheme"]:
                continue

            # Loopback scope matching
            if rule["is_loopback"]:
                if target_is_loopback and (rule["has_port_wildcard"] or port == rule["port"]):
                    return True, (
                        f"Target URL '{clean_url}' is within authorized scope '{rule['raw']}' "
                        f"(loopback alias '{hostname}', port {port})."
                    )
            else:
                # Non-loopback exact match
                if hostname == rule["host"] and (rule["has_port_wildcard"] or port == rule["port"]):
                    return True, f"Target URL '{clean_url}' matches authorized scope '{rule['raw']}'."

        # Rejection reason
        if target_is_loopback:
            expected_ports = list(set(r["port"] for r in self.rules if r["is_loopback"] and r["port"] is not None))
            if expected_ports and port not in expected_ports:
                return False, (
                    f"Target URL '{clean_url}' port {port} rejected: does not match authorized port(s) {expected_ports}."
                )
        return False, (
            f"Target URL '{clean_url}' host '{hostname}' is outside authorized scope "
            f"({self.authorized_scopes[0] if self.authorized_scopes else 'None'})."
        )

    def evaluate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates action against target URL scope rules and outputs ALLOW or DENY.
        """
        f_id = finding.get("id", "UNKNOWN")
        title = finding.get("title", "Untitled Alert")
        url = finding.get("affected_asset", {}).get("url", "")
        action = finding.get("suggested_action") or finding.get("action") or "manual_review"

        in_scope, reason = self.check_scope_detailed(url)
        decision = "ALLOW" if in_scope else "DENY"
        if in_scope:
            full_reason = f"{reason} Tactical action '{action}' permitted."
        else:
            full_reason = f"{reason} Tactical action '{action}' blocked by Policy Gate."

        return {
            "finding_id": f_id,
            "title": title,
            "target_url": url,
            "suggested_action": action,
            "decision": decision,
            "reason": full_reason,
            "authorized_scopes": self.authorized_scopes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class MasterOrchestrator:
    """
    Coordinates end-to-end Project Zero-Day execution pipeline.
    """

    def __init__(
        self,
        workspace_dir: Optional[Path] = None,
        target_url: str = "http://localhost:3000",
        container_target_url: Optional[str] = None,
        authorized_scopes: Optional[List[str]] = None,
        scanners: Optional[List[str]] = None,
        use_sample: bool = False,
        ollama_url: str = "http://127.0.0.1:11434",
        ollama_timeout: Optional[float] = None,
        allow_arbitrary_loopback_ports: bool = True,
        validate_target: bool = True,
        skip_reachability_check: bool = False,
    ):
        self.workspace_dir = workspace_dir or PROJECT_ROOT
        self.use_sample = use_sample
        self.scanners = scanners or ["zap", "nuclei"]
        self.ollama_url = ollama_url
        self.ollama_timeout = ollama_timeout if ollama_timeout is not None else float(os.environ.get("OLLAMA_TIMEOUT", "90.0"))

        # 1. Target URL format, scheme, host, and port validation
        if validate_target and not self.use_sample:
            target_meta = parse_and_validate_target(target_url, enforce_local=True)
            self.target_url = target_meta["normalized_url"]
            if not skip_reachability_check:
                verify_target_reachability(self.target_url, enforce_local=True)
        else:
            self.target_url = target_url

        # 2. Automatically map Windows-host loopback to Docker container address
        if container_target_url:
            self.container_target_url = container_target_url
        else:
            self.container_target_url = map_to_container_target(self.target_url)

        # 3. Policy Gate initialized with authorized scopes or reusable local policy
        if authorized_scopes:
            scope_list = authorized_scopes
            is_wildcard = any("*" in s or "local" in s.lower() or "127.0.0.1" in s or "::1" in s for s in scope_list)
            self.policy_gate = PolicyGate(
                authorized_scopes=scope_list,
                allow_arbitrary_loopback_ports=allow_arbitrary_loopback_ports if is_wildcard else False,
            )
        else:
            # Reusable local-target policy allowing arbitrary loopback ports
            scope_list = [self.target_url, "http://localhost:*", "http://127.0.0.1:*"]
            self.policy_gate = PolicyGate(
                authorized_scopes=scope_list,
                allow_arbitrary_loopback_ports=True,
            )

        # Execution tracking
        self.run_id = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        self.artifacts_dir = self.workspace_dir / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Run-isolated artifacts directory
        self.run_artifacts_dir = self.artifacts_dir / self.run_id
        self.run_artifacts_dir.mkdir(parents=True, exist_ok=True)

        # File paths (run-isolated scanner outputs)
        self.zap_live_file = self.run_artifacts_dir / "zap-findings.json"
        self.nuclei_live_file = self.run_artifacts_dir / "nuclei-findings.jsonl"
        self.sample_zap_file = self.workspace_dir / "zap-findings.json"

        self.normalized_file = self.workspace_dir / "normalized_findings.json"
        self.prioritized_file = self.workspace_dir / "prioritized_findings.json"
        self.verification_file = self.workspace_dir / "verification_results.json"
        self.decision_log_file = self.workspace_dir / "decision_log.json"
        self.report_html_file = self.workspace_dir / "security_report.html"
        self.report_json_file = self.workspace_dir / "security_report.json"

        # Runtime metadata & pipeline status tracking
        self.scan_metadata: Dict[str, Any] = {}
        self.stage_timings: Dict[str, float] = {}
        self.stage_statuses: Dict[str, str] = {}
        self.scanner_errors: Dict[str, str] = {}
        self.pipeline_status = "PENDING"

    def run_stage_0_scanner_suite(self) -> Dict[str, Any]:
        """
        Stage 0: Pre-flight checks and automated multi-scanner execution (OWASP ZAP + Nuclei).
        """
        stage_start = time.perf_counter()
        print("\n[STAGE 0/6] Automated Multi-Scanner Suite Execution...")
        print(f"[*] Run ID:              {self.run_id}")
        print(f"[*] Target Endpoint:     {self.target_url}")
        print(f"[*] Container Target:    {self.container_target_url}")
        print(f"[*] Selected Scanners:   {', '.join(self.scanners)}")

        if self.use_sample:
            print("[*] --use-sample flag set: Skipping live container scanning; utilizing sample fixtures.")
            self.stage_timings["stage_0_scanning"] = round(time.perf_counter() - stage_start, 2)
            self.stage_statuses["stage_0_scanning"] = "SKIPPED_SAMPLE_MODE"
            return {"status": "SKIPPED_SAMPLE_MODE"}

        # Run multi-scanner execution with run-isolated directory
        scan_results = run_multi_scanner_suite(
            target_url=self.target_url,
            container_target_url=self.container_target_url,
            artifacts_dir=self.run_artifacts_dir,
            scanners=self.scanners,
            run_id=self.run_id,
            zap_filename="zap-findings.json",
            nuclei_filename="nuclei-findings.jsonl",
        )
        self.scan_metadata = scan_results
        self.stage_timings["stage_0_scanning"] = round(time.perf_counter() - stage_start, 2)

        # Track scanner errors and stage status truthfully
        all_failed = True
        any_failed = False
        for sc in self.scanners:
            sc_meta = scan_results.get(sc, {})
            if sc_meta.get("status") == "ERROR":
                any_failed = True
                self.scanner_errors[sc] = sc_meta.get("error", "Unknown error")
            elif sc_meta.get("status") == "SUCCESS":
                all_failed = False

        if all_failed and len(self.scanners) > 0:
            self.stage_statuses["stage_0_scanning"] = "FAILED"
            print(f"[!] All requested scanners failed in Stage 0: {self.scanner_errors}")
        elif any_failed:
            self.stage_statuses["stage_0_scanning"] = "PARTIAL_SUCCESS"
            print(f"[WARN] Partial scanner completion in Stage 0: {self.scanner_errors}")
        else:
            self.stage_statuses["stage_0_scanning"] = "SUCCESS"

        print(f"[+] Stage 0 completed in {self.stage_timings['stage_0_scanning']}s (status: {self.stage_statuses['stage_0_scanning']})")
        return scan_results

    def run_stage_1_normalization(self) -> List[Dict[str, Any]]:
        """
        Stage 1: Normalize raw scanner findings and perform cross-scanner deduplication.
        """
        stage_start = time.perf_counter()
        print("\n[STAGE 1/6] Finding Ingestion, Normalization & Deduplication...")
        raw_combined_findings: List[Dict[str, Any]] = []

        canonical_host = urllib.parse.urlparse(self.target_url).netloc

        if self.use_sample:
            # Explicit sample fixture execution
            print(f"[*] Utilizing sample fixture: {self.sample_zap_file.name}...")
            if not self.sample_zap_file.is_file():
                raise FileNotFoundError(f"Sample fixture not found at: {self.sample_zap_file}")
            zap_norm = normalize_findings.normalize_zap_findings(
                input_path=self.sample_zap_file,
                output_path=self.run_artifacts_dir / "normalized-zap-sample.json",
                canonical_host=canonical_host,
                run_id=self.run_id,
            )
            raw_combined_findings.extend(zap_norm)
            self.stage_statuses["stage_1_normalization"] = "SUCCESS"
        else:
            # LIVE MODE: Ingest outputs produced ONLY by the current run
            # Ingest live ZAP findings if ZAP was requested and produced output
            if "zap" in self.scanners:
                if self.zap_live_file.is_file():
                    print(f"[*] Normalizing fresh live ZAP findings from {self.zap_live_file.name}...")
                    zap_norm = normalize_findings.normalize_zap_findings(
                        input_path=self.zap_live_file,
                        output_path=self.run_artifacts_dir / "normalized-zap-live.json",
                        canonical_host=canonical_host,
                        expected_target_url=self.target_url,
                        run_id=self.run_id,
                    )
                    raw_combined_findings.extend(zap_norm)
                    # Maintain top-level live reference for fresh validated output
                    try:
                        shutil.copyfile(self.zap_live_file, self.artifacts_dir / "zap-findings-live.json")
                    except Exception:
                        pass
                else:
                    zap_status = self.scan_metadata.get("zap", {}).get("status", "NOT_RUN")
                    print(f"[*] ZAP status: {zap_status} (0 findings or no output file generated).")

            # Ingest live Nuclei findings if Nuclei was requested and produced output
            if "nuclei" in self.scanners:
                if self.nuclei_live_file.is_file():
                    print(f"[*] Normalizing fresh live Nuclei findings from {self.nuclei_live_file.name}...")
                    nuclei_norm = normalize_nuclei_findings(
                        input_path=self.nuclei_live_file,
                        output_path=self.run_artifacts_dir / "normalized-nuclei-live.json",
                        canonical_host=canonical_host,
                        expected_target_url=self.target_url,
                        run_id=self.run_id,
                    )
                    raw_combined_findings.extend(nuclei_norm)
                    # Maintain top-level live reference for fresh validated output
                    try:
                        shutil.copyfile(self.nuclei_live_file, self.artifacts_dir / "nuclei-findings-live.jsonl")
                    except Exception:
                        pass
                else:
                    nuclei_status = self.scan_metadata.get("nuclei", {}).get("status", "NOT_RUN")
                    print(f"[*] Nuclei status: {nuclei_status} (0 findings or no output file generated).")

            if self.stage_statuses.get("stage_0_scanning") == "FAILED":
                self.stage_statuses["stage_1_normalization"] = "FAILED"
            else:
                self.stage_statuses["stage_1_normalization"] = "SUCCESS"

        # Cross-scanner deduplication
        deduped_findings, dedup_stats = deduplicate_multi_scanner_findings(raw_combined_findings)
        print(f"[+] Multi-Scanner Deduplication Complete:")
        print(f"    - Raw Detections:       {dedup_stats['raw_total']}")
        print(f"    - Deduplicated Unique:  {dedup_stats['deduplicated_total']}")
        print(f"    - Overlaps Corroborated:{dedup_stats['corroborated_count']}")

        # Save to canonical normalized_findings.json
        with open(self.normalized_file, "w", encoding="utf-8") as f:
            json.dump(deduped_findings, f, indent=2)

        # Also preserve in run-isolated artifacts directory
        with open(self.run_artifacts_dir / "normalized_findings.json", "w", encoding="utf-8") as f:
            json.dump(deduped_findings, f, indent=2)
        with open(self.artifacts_dir / "normalized_findings.json", "w", encoding="utf-8") as f:
            json.dump(deduped_findings, f, indent=2)

        self.stage_timings["stage_1_normalization"] = round(time.perf_counter() - stage_start, 2)
        print(f"[+] Loaded {len(deduped_findings)} canonical findings -> {self.normalized_file.name}")
        return deduped_findings

    def run_stage_2_prioritization(self) -> List[Dict[str, Any]]:
        """
        Stage 2: Priority Grouping (P1-P4) & Deterministic Action Heuristics.
        """
        stage_start = time.perf_counter()
        print("\n[STAGE 2/6] Decision & Prioritization Engine (FR-02)...")
        prioritized = run_decision_engine(
            input_path=self.normalized_file,
            output_path=self.prioritized_file,
        )
        self.stage_timings["stage_2_prioritization"] = round(time.perf_counter() - stage_start, 2)
        print(f"[+] Prioritized {len(prioritized)} findings -> {self.prioritized_file.name}")
        return prioritized

    def run_stage_3_rag_and_advisory(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Stage 3: Pwn Scenarios RAG lookup and Ollama Gemma LLM advisory.
        """
        stage_start = time.perf_counter()
        print("\n[STAGE 3/6] Scenario Dataset RAG & Gemma AI Advisory (FR-01)...")
        client = GemmaAdvisoryClient(base_url=self.ollama_url, timeout=self.ollama_timeout)
        is_online, health_msg = client.check_health()
        print(f"[*] Ollama Service: {'ONLINE' if is_online else 'OFFLINE (Rule-based Fallback Active)'}")
        print(f"[*] Status: {health_msg}")

        needs_advisory = any(
            not f.get("ai_advisory", {}).get("gemma_explanation")
            for f in findings
        )

        if needs_advisory:
            print("[*] Generating advisory enrichments via Gemma & SQLite FTS5 RAG...")
            enrich_findings_file(
                input_path=self.prioritized_file,
                output_path=self.prioritized_file,
                client=client,
            )
            with open(self.prioritized_file, "r", encoding="utf-8") as f:
                findings = json.load(f)
        else:
            print(f"[+] Verified RAG and AI advisory metadata on all {len(findings)} findings.")

        self.stage_timings["stage_3_rag_advisory"] = round(time.perf_counter() - stage_start, 2)
        return findings

    def run_stage_4_policy_gate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Stage 4: Policy Gate Scope Evaluation & Decision Log (FR-03).
        """
        stage_start = time.perf_counter()
        print("\n[STAGE 4/6] Policy Gate Scope Enforcement (FR-03)...")
        decision_entries = []
        allow_count = 0
        deny_count = 0

        for f in findings:
            pol_eval = self.policy_gate.evaluate_finding(f)
            f["policy_evaluation"] = {
                "decision": pol_eval["decision"],
                "reason": pol_eval["reason"],
                "authorized_scopes": pol_eval["authorized_scopes"],
                "evaluated_at": pol_eval["timestamp"],
            }
            decision_entries.append(pol_eval)
            if pol_eval["decision"] == "ALLOW":
                allow_count += 1
            else:
                deny_count += 1

        decision_log = {
            "run_id": self.run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "authorized_scopes": self.policy_gate.authorized_scopes,
            "total_evaluations": len(decision_entries),
            "allow_count": allow_count,
            "deny_count": deny_count,
            "decisions": decision_entries,
        }

        with open(self.decision_log_file, "w", encoding="utf-8") as f:
            json.dump(decision_log, f, indent=2)

        self.stage_timings["stage_4_policy_gate"] = round(time.perf_counter() - stage_start, 2)
        print(f"[+] Evaluated {len(findings)} findings against authorized scope: {self.policy_gate.authorized_scopes[0]}")
        print(f"    - ALLOWED: {allow_count}")
        print(f"    - DENIED:  {deny_count}")
        print(f"[+] Authoritative policy log written to {self.decision_log_file.name}")

        return findings

    def run_investigation_loop(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Milestone 3: Bounded Autonomous Investigation Loop driven by the Random Forest model.
        """
        stage_start = time.perf_counter()
        print("\n[INVESTIGATION LOOP] Autonomous Investigation Trajectories (Milestone 3)...")
        controller = InvestigationController(
            policy_gate=self.policy_gate,
            target_url=self.target_url,
            is_live=(not self.use_sample),
            max_steps_per_finding=4,
            max_total_requests=50,
        )
        inv_result = controller.run_investigation_suite(findings)
        investigated = inv_result["findings"]
        self.stage_timings["investigation_loop"] = round(time.perf_counter() - stage_start, 2)

        # Update decision_log.json with trajectory telemetry while preserving policy decisions
        if self.decision_log_file.is_file():
            try:
                with open(self.decision_log_file, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
                log_data["investigation_summary"] = inv_result["summary"]
                log_data["trajectories"] = {
                    f.get("id"): f.get("investigation_trajectory", {})
                    for f in investigated
                }
                with open(self.decision_log_file, "w", encoding="utf-8") as f:
                    json.dump(log_data, f, indent=2)
            except Exception as e:
                print(f"[WARN] Could not update decision_log with trajectories: {e}")

        # Also write artifacts/investigation_history.json
        inv_history_file = self.artifacts_dir / "investigation_history.json"
        with open(inv_history_file, "w", encoding="utf-8") as f:
            json.dump(inv_result, f, indent=2)

        return investigated

    def run_stage_5_verification(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Stage 5: Evidence Verification Engine (FR-04 & Milestone 2).
        """
        stage_start = time.perf_counter()
        is_live = not self.use_sample
        print(f"\n[STAGE 5/6] Evidence Verification Engine ({'LIVE ACTIVE VERIFICATION' if is_live else 'OFFLINE SAMPLE INVARIANT'})...")
        # Save current prioritized state with policy evaluations
        with open(self.prioritized_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        verified_results = run_verification_engine(
            input_path=self.prioritized_file,
            output_path=self.verification_file,
            live_verification=is_live,
            target_url=self.target_url,
            policy_gate=self.policy_gate,
        )

        with open(self.verification_file, "w", encoding="utf-8") as f:
            json.dump(verified_results, f, indent=2)

        self.stage_timings["stage_5_verification"] = round(time.perf_counter() - stage_start, 2)
        v_counts = {
            s: sum(1 for f in verified_results if f.get("verification", {}).get("status") == s)
            for s in ["CONFIRMED", "REJECTED", "MANUAL_REVIEW", "NEEDS_VERIFICATION"]
        }
        print(f"[+] Verification completed in {self.stage_timings['stage_5_verification']}s:")
        print(f"    - CONFIRMED:         {v_counts['CONFIRMED']}")
        print(f"    - REJECTED:          {v_counts['REJECTED']}")
        print(f"    - MANUAL_REVIEW:     {v_counts['MANUAL_REVIEW']}")
        print(f"    - NEEDS_VERIFICATION:{v_counts['NEEDS_VERIFICATION']}")
        return verified_results

    def run_stage_6_report_generation(self) -> Dict[str, Any]:
        """
        Stage 6: Interactive Dashboard & Report Generation (FR-05).
        """
        stage_start = time.perf_counter()
        print("\n[STAGE 6/6] Interactive Dashboard & Report Generation (FR-05)...")
        report_data = generate_security_report(
            findings_file=self.verification_file,
            decision_log_file=self.decision_log_file,
            output_html_file=self.report_html_file,
            output_json_file=self.report_json_file,
            target_url=self.target_url,
            run_id=self.run_id,
            pipeline_status=self.pipeline_status,
            scanners_executed=self.scanners,
            stage_statuses=self.stage_statuses,
            scan_metadata=self.scan_metadata,
            provenance="SAMPLE FIXTURE" if self.use_sample else "LIVE SCAN",
        )
        self.stage_timings["stage_6_reporting"] = round(time.perf_counter() - stage_start, 2)
        self.stage_statuses["stage_6_reporting"] = "SUCCESS"
        return report_data

    def execute_pipeline(self) -> Dict[str, Any]:
        """
        Executes complete end-to-end multi-scanner analysis pipeline.
        """
        total_start_time = time.perf_counter()
        print("============================================================")
        print("Project Zero-Day: Automated Multi-Scanner Security Pipeline")
        print("============================================================")
        print(f"Run ID:                      {self.run_id}")
        print(f"Workspace Directory:         {self.workspace_dir}")
        print(f"Target URL:                  {self.target_url}")
        print(f"Authorized Policy Scope:     {self.policy_gate.authorized_scopes[0]}")
        print(f"Execution Started At:        {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("------------------------------------------------------------")

        try:
            # 0. Multi-Scanner Execution
            self.run_stage_0_scanner_suite()

            # 1. Ingestion, Normalization & Deduplication
            findings = self.run_stage_1_normalization()

            # 2. Prioritization & Action Selection
            findings = self.run_stage_2_prioritization()

            # 3. RAG & AI Advisory
            findings = self.run_stage_3_rag_and_advisory(findings)

            # 4. Policy Gate Scope Evaluation
            findings = self.run_stage_4_policy_gate(findings)

            # 4b. Bounded Autonomous Investigation Loop (Milestone 3)
            findings = self.run_investigation_loop(findings)

            # 5. Evidence Verification
            findings = self.run_stage_5_verification(findings)

            # Determine authoritative pipeline status prior to final report generation
            if self.stage_statuses.get("stage_0_scanning") == "FAILED":
                self.pipeline_status = "FAILED"
            elif self.stage_statuses.get("stage_0_scanning") == "PARTIAL_SUCCESS":
                self.pipeline_status = "PARTIAL_SUCCESS"
            elif any(s == "FAILED" for s in self.stage_statuses.values()):
                self.pipeline_status = "FAILED"
            else:
                self.pipeline_status = "SUCCESS"

            # 6. Report Generation
            report_data = self.run_stage_6_report_generation()

            # Update decision log with final pipeline status
            if self.decision_log_file.is_file():
                try:
                    with open(self.decision_log_file, "r", encoding="utf-8") as f:
                        dec_data = json.load(f)
                    dec_data["pipeline_status"] = self.pipeline_status
                    dec_data["stage_statuses"] = self.stage_statuses
                    dec_data["target_url"] = self.target_url
                    with open(self.decision_log_file, "w", encoding="utf-8") as f:
                        json.dump(dec_data, f, indent=2)
                except Exception:
                    pass

            total_elapsed_sec = time.perf_counter() - total_start_time
            prov = report_data.get("report_metadata", {}).get("data_provenance", "SAMPLE FIXTURE")
            prio_dist = report_data.get("report_metadata", {}).get("priority_distribution", {})
            verif_dist = report_data.get("report_metadata", {}).get("verification_status", {})
            pol_dist = report_data.get("report_metadata", {}).get("policy_distribution", {})

            print("\n============================================================")
            print("Master Orchestration Complete: Pipeline Summary")
            print("============================================================")
            print(f"Run ID:                      {self.run_id}")
            print(f"Pipeline Execution Status:   {self.pipeline_status}")
            print(f"Total Execution Runtime:     {total_elapsed_sec:.2f} seconds")
            print(f"Data Provenance Label:       {prov}")
            print(f"Total Findings Processed:    {len(findings)}")
            print(f"Priority Distribution:       P1={prio_dist.get('P1', 0)}, P2={prio_dist.get('P2', 0)}, P3={prio_dist.get('P3', 0)}, P4={prio_dist.get('P4', 0)}")
            print(f"Policy Gate Scope Decisions: ALLOW={pol_dist.get('ALLOW', 0)}, DENY={pol_dist.get('DENY', 0)}")
            print(f"Verification Breakdown:      CONFIRMED={verif_dist.get('CONFIRMED', 0)}, REJECTED={verif_dist.get('REJECTED', 0)}, MANUAL_REVIEW={verif_dist.get('MANUAL_REVIEW', 0)}, NEEDS_VERIFICATION={verif_dist.get('NEEDS_VERIFICATION', 0)}")
            print(f"HTML Report Dashboard:       {self.report_html_file}")
            print(f"Structured JSON Report:      {self.report_json_file}")
            print(f"Authoritative Decision Log:  {self.decision_log_file}")
            print("============================================================")

            return report_data

        except Exception as exc:
            print(f"\n[CRITICAL ERROR] Pipeline orchestration halted: {exc}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Project Zero-Day Master Orchestrator")
    parser.add_argument("--target", default="http://localhost:3000", help="Host-accessible target endpoint (e.g. http://localhost:3000, http://127.0.0.1:8000, http://localhost:5173)")
    parser.add_argument("--scope", default=None, help="Authorized target scope URL (default: reusable local loopback policy)")
    parser.add_argument("--container-target", default=None, help="Container-accessible target URL (default: auto-mapped from --target)")
    parser.add_argument("--scanners", default="zap,nuclei", help="Comma-separated scanner list (zap, nuclei)")
    parser.add_argument("--use-sample", action="store_true", help="Force sample fixture execution without live scanning")
    parser.add_argument("--open-report", action="store_true", help="Automatically open security_report.html in default browser")
    parser.add_argument("--ollama-timeout", type=float, default=float(os.environ.get("OLLAMA_TIMEOUT", "90.0")), help="Timeout in seconds for Ollama LLM inference")
    parser.add_argument("--skip-reachability-check", action="store_true", help="Skip pre-flight reachability probe")
    args = parser.parse_args()

    scanners_list = [s.strip().lower() for s in args.scanners.split(",") if s.strip()]

    orchestrator = MasterOrchestrator(
        target_url=args.target,
        container_target_url=args.container_target,
        authorized_scopes=[args.scope] if args.scope else None,
        scanners=scanners_list,
        use_sample=args.use_sample,
        ollama_timeout=args.ollama_timeout,
        skip_reachability_check=args.skip_reachability_check,
    )
    report = orchestrator.execute_pipeline()

    if args.open_report:
        try:
            import webbrowser
            print(f"\n[*] Launching browser to display report: {orchestrator.report_html_file.as_uri()}")
            webbrowser.open(orchestrator.report_html_file.as_uri())
        except Exception as err:
            print(f"[WARN] Could not automatically open browser: {err}")


if __name__ == "__main__":
    main()
