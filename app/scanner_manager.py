#!/usr/bin/env python3
"""
Project Zero-Day: Automated Multi-Scanner Manager
Script: app/scanner_manager.py
Objective: Manage local target readiness (OWASP Juice Shop) and orchestrate
           automated, non-destructive scans via OWASP ZAP and ProjectDiscovery Nuclei.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.target_validator import (
    map_to_container_target,
    verify_docker_container_connectivity,
    TargetUnreachableError,
    DockerConnectivityError,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"


def check_docker_daemon() -> Tuple[bool, str]:
    """
    Validates Docker CLI availability and daemon responsiveness.
    """
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return False, "Docker CLI binary 'docker' not found in PATH. Please install Docker Desktop."
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return False, f"Docker daemon is not running or unreachable: {proc.stderr.strip()[:200]}"
        return True, "Docker daemon is active and responsive."
    except subprocess.TimeoutExpired:
        return False, "Docker daemon check timed out after 10s. Verify Docker Desktop status."
    except Exception as exc:
        return False, f"Unexpected error checking Docker: {exc}"


def check_target_http(target_url: str = "http://localhost:3000", timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Checks if the target endpoint is reachable via HTTP.
    """
    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "ProjectZeroDay-HealthCheck/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            if 200 <= status < 400:
                return True, f"Target '{target_url}' reachable (HTTP {status})"
            return False, f"Target '{target_url}' returned unexpected status: HTTP {status}"
    except urllib.error.HTTPError as http_err:
        return True, f"Target '{target_url}' responded (HTTP {http_err.code})"
    except Exception as exc:
        return False, f"Target '{target_url}' unreachable: {exc}"


def ensure_juice_shop_container(
    target_url: str = "http://localhost:3000",
    container_name: str = "juice-shop",
    image: str = "bkimminich/juice-shop:latest",
    port_mapping: str = "3000:3000",
    max_wait_sec: int = 30,
) -> Tuple[bool, str]:
    """
    Ensures the target OWASP Juice Shop container is running.
    Reuses existing container if stopped, creates it if missing, and verifies reachability.
    """
    # 1. Quick reachability check
    is_up, msg = check_target_http(target_url, timeout=2.0)
    if is_up:
        return True, f"Target Juice Shop is already active: {msg}"

    # 2. Check if Docker is available
    docker_ok, docker_msg = check_docker_daemon()
    if not docker_ok:
        return False, f"Cannot start Juice Shop: {docker_msg}"

    # 3. Check container existence
    try:
        proc = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^/{container_name}$", "--format", "{{.ID}}|{{.Status}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        output = proc.stdout.strip()
        if output:
            cid, status = output.split("|", 1)
            print(f"[*] Found existing '{container_name}' container ({cid[:12]}, {status}). Starting...")
            subprocess.run(["docker", "start", container_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            print(f"[*] Container '{container_name}' does not exist. Creating from {image}...")
            subprocess.run(
                ["docker", "run", "-d", "-p", port_mapping, "--name", container_name, image],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # 4. Poll until target is reachable
        print(f"[*] Waiting for Juice Shop at {target_url} to become ready (max {max_wait_sec}s)...")
        start = time.perf_counter()
        while time.perf_counter() - start < max_wait_sec:
            time.sleep(2)
            up, check_msg = check_target_http(target_url, timeout=2.0)
            if up:
                return True, f"Juice Shop successfully started and responding at {target_url}"

        return False, f"Juice Shop container started but did not respond within {max_wait_sec}s"

    except Exception as exc:
        return False, f"Failed to ensure Juice Shop container: {exc}"


def get_docker_volume_path(local_path: Path) -> str:
    """
    Formats a local filesystem path for Docker -v volume mounting across Windows/Linux.
    """
    p = local_path.resolve()
    # Normalize Windows backslashes to forward slashes
    return str(p).replace("\\", "/")


def run_zap_baseline_scan(
    target_container_url: str = "http://host.docker.internal:3000",
    artifacts_dir: Optional[Path] = None,
    output_filename: str = "zap-findings-live.json",
    spider_mins: int = 2,
    zap_image: str = "ghcr.io/zaproxy/zaproxy:stable",
    timeout_sec: int = 300,
) -> Dict[str, Any]:
    """
    Executes official OWASP ZAP Docker baseline scanner against target container URL.
    Treats exit codes 0, 1, and 2 as successful scans (0=clean, 1=warns, 2=fails/highs).
    Treats exit codes 3+ as scan failure.
    """
    artifacts_dir = artifacts_dir or DEFAULT_ARTIFACTS_DIR
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    json_report_file = artifacts_dir / output_filename
    html_report_file = artifacts_dir / output_filename.replace(".json", ".html")

    # Remove previous run artifacts in this target directory to guarantee fresh provenance
    if json_report_file.exists():
        json_report_file.unlink()
    if html_report_file.exists():
        html_report_file.unlink()

    vol_mount = f"{get_docker_volume_path(artifacts_dir)}:/zap/wrk/:rw"

    cmd = [
        "docker", "run", "--rm",
        "-v", vol_mount,
        zap_image,
        "zap-baseline.py",
        "-t", target_container_url,
        "-J", json_report_file.name,
        "-r", html_report_file.name,
        "-m", str(spider_mins),
        "-I",  # Do not return failure exit code on warnings
    ]

    print(f"\n[SCANNER: OWASP ZAP] Starting automated baseline scan against {target_container_url}...")
    print(f"[*] Command: {' '.join(cmd[:6])} ... -t {target_container_url} -J {json_report_file.name}")
    start_time = time.perf_counter()

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
        )
        elapsed_sec = round(time.perf_counter() - start_time, 2)
        exit_code = proc.returncode

        # ZAP exit code semantics:
        # 0: Clean, 1: Warnings found, 2: Fails/Highs found, 3+: General ZAP execution error
        is_success_code = exit_code in [0, 1, 2]

        if not json_report_file.is_file():
            err_snippet = (proc.stderr or proc.stdout or "No error output").strip()[:400]
            print(f"[!] ZAP baseline scan produced no report (exit code {exit_code}): {err_snippet}", file=sys.stderr)
            return {
                "scanner": "OWASP ZAP",
                "status": "ERROR",
                "exit_code": exit_code,
                "error": f"ZAP finished with code {exit_code} but produced no JSON output: {err_snippet}",
                "duration_sec": elapsed_sec,
                "output_file": str(json_report_file),
                "html_report_file": None,
                "raw_findings_count": 0,
                "scanner_version": "2.15.0/stable",
                "target": target_container_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Validate JSON content
        try:
            with open(json_report_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as j_err:
            return {
                "scanner": "OWASP ZAP",
                "status": "ERROR",
                "exit_code": exit_code,
                "error": f"Invalid JSON in ZAP output: {j_err}",
                "duration_sec": elapsed_sec,
                "output_file": str(json_report_file),
                "html_report_file": None,
                "raw_findings_count": 0,
                "scanner_version": "2.15.0/stable",
                "target": target_container_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        if not isinstance(data, dict):
            return {
                "scanner": "OWASP ZAP",
                "status": "ERROR",
                "exit_code": exit_code,
                "error": f"ZAP output {json_report_file} does not contain valid JSON object.",
                "duration_sec": elapsed_sec,
                "output_file": str(json_report_file),
                "html_report_file": None,
                "raw_findings_count": 0,
                "scanner_version": "2.15.0/stable",
                "target": target_container_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Count parsed raw alerts
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        raw_alerts_count = sum(len(s.get("alerts", [])) for s in sites if isinstance(s, dict))
        zap_version = str(data.get("@version", "2.15.0/stable"))
        scan_status = "SUCCESS" if is_success_code else "ERROR"

        print(f"[+] OWASP ZAP baseline scan completed in {elapsed_sec}s (exit code {exit_code}, status {scan_status}).")
        print(f"[+] Live output written to: {json_report_file}")
        print(f"[+] Total raw alerts discovered: {raw_alerts_count}")

        return {
            "scanner": "OWASP ZAP",
            "status": scan_status,
            "exit_code": exit_code,
            "duration_sec": elapsed_sec,
            "output_file": str(json_report_file),
            "html_report_file": str(html_report_file) if html_report_file.is_file() else None,
            "raw_findings_count": raw_alerts_count,
            "scanner_version": zap_version,
            "target": target_container_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        elapsed_sec = round(time.perf_counter() - start_time, 2)
        return {
            "scanner": "OWASP ZAP",
            "status": "ERROR",
            "exit_code": -1,
            "error": f"ZAP baseline scan timed out after {timeout_sec}s.",
            "duration_sec": elapsed_sec,
            "output_file": str(json_report_file),
            "html_report_file": None,
            "raw_findings_count": 0,
            "scanner_version": "2.15.0/stable",
            "target": target_container_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        elapsed_sec = round(time.perf_counter() - start_time, 2)
        print(f"[!] ZAP baseline scan error: {exc}", file=sys.stderr)
        return {
            "scanner": "OWASP ZAP",
            "status": "ERROR",
            "exit_code": -1,
            "error": str(exc),
            "duration_sec": elapsed_sec,
            "output_file": str(json_report_file),
            "html_report_file": None,
            "raw_findings_count": 0,
            "scanner_version": "2.15.0/stable",
            "target": target_container_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def ensure_nuclei_templates_volume(volume_name: str = "nuclei-templates", nuclei_image: str = "projectdiscovery/nuclei:v3.3.8") -> bool:
    """
    Ensures persistent Docker volume for Nuclei templates exists and is populated.
    """
    try:
        proc = subprocess.run(["docker", "volume", "inspect", volume_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            print(f"[*] Initializing persistent Docker volume '{volume_name}' for Nuclei templates...")
            subprocess.run(["docker", "volume", "create", volume_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["docker", "run", "--rm", "-v", f"{volume_name}:/root/nuclei-templates", nuclei_image, "-update-templates"], timeout=120, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except Exception as exc:
        print(f"[WARN] Could not ensure nuclei templates volume: {exc}", file=sys.stderr)
        return False


def run_nuclei_baseline_scan(
    target_container_url: str = "http://host.docker.internal:3000",
    artifacts_dir: Optional[Path] = None,
    output_filename: str = "nuclei-findings-live.jsonl",
    nuclei_image: str = "projectdiscovery/nuclei:v3.3.8",
    timeout_sec: int = 180,
) -> Dict[str, Any]:
    """
    Executes ProjectDiscovery Nuclei baseline scanner against target container URL.
    Outputs findings in JSONL format to artifacts_dir.
    """
    artifacts_dir = artifacts_dir or DEFAULT_ARTIFACTS_DIR
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    jsonl_output_file = artifacts_dir / output_filename
    if jsonl_output_file.exists():
        jsonl_output_file.unlink()

    ensure_nuclei_templates_volume(nuclei_image=nuclei_image)
    vol_mount = f"{get_docker_volume_path(artifacts_dir)}:/app/artifacts:rw"

    cmd = [
        "docker", "run", "--rm",
        "-v", "nuclei-templates:/root/nuclei-templates:rw",
        "-v", vol_mount,
        nuclei_image,
        "-u", target_container_url,
        "-tags", "cve,misconfig,exposure",
        "-etags", "fuzz,dos",
        "-severity", "info,low,medium,high,critical",
        "-timeout", "3",
        "-retries", "0",
        "-mhe", "3",
        "-duc",
        "-jsonl",
        "-o", f"/app/artifacts/{output_filename}",
        "-silent",
    ]

    print(f"\n[SCANNER: Nuclei] Starting automated baseline scan against {target_container_url}...")
    print(f"[*] Command: {' '.join(cmd[:6])} ... -u {target_container_url} -o /app/artifacts/{output_filename}")
    start_time = time.perf_counter()

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
        )
        elapsed_sec = round(time.perf_counter() - start_time, 2)
        exit_code = proc.returncode

        # Nuclei exits 0 on success
        if not jsonl_output_file.is_file():
            # If completed with 0 findings, file might not have been created; touch empty file
            jsonl_output_file.touch()

        # Count parsed records
        raw_count = 0
        with open(jsonl_output_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    raw_count += 1

        is_clean_success = (exit_code == 0)
        status = "SUCCESS" if is_clean_success else "ERROR"
        error_msg = None
        if not is_clean_success and raw_count == 0:
            error_msg = (proc.stderr or proc.stdout or f"Nuclei exited with code {exit_code}").strip()[:300]
            print(f"[!] Nuclei execution error: {error_msg}", file=sys.stderr)

        print(f"[+] Nuclei baseline scan completed in {elapsed_sec}s (exit code {exit_code}, status {status}).")
        print(f"[+] Live output written to: {jsonl_output_file}")
        print(f"[+] Total raw records discovered: {raw_count}")

        return {
            "scanner": "ProjectDiscovery Nuclei",
            "status": status,
            "exit_code": exit_code,
            "error": error_msg,
            "duration_sec": elapsed_sec,
            "output_file": str(jsonl_output_file),
            "raw_findings_count": raw_count,
            "scanner_version": "v3.3.8",
            "target": target_container_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except subprocess.TimeoutExpired:
        elapsed_sec = round(time.perf_counter() - start_time, 2)
        return {
            "scanner": "ProjectDiscovery Nuclei",
            "status": "ERROR",
            "exit_code": -1,
            "error": f"Nuclei baseline scan timed out after {timeout_sec}s.",
            "duration_sec": elapsed_sec,
            "output_file": str(jsonl_output_file),
            "raw_findings_count": 0,
            "scanner_version": "v3.3.8",
            "target": target_container_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        elapsed_sec = round(time.perf_counter() - start_time, 2)
        print(f"[!] Nuclei baseline scan error: {exc}", file=sys.stderr)
        return {
            "scanner": "ProjectDiscovery Nuclei",
            "status": "ERROR",
            "exit_code": -1,
            "error": str(exc),
            "duration_sec": elapsed_sec,
            "output_file": str(jsonl_output_file),
            "raw_findings_count": 0,
            "scanner_version": "v3.3.8",
            "target": target_container_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def run_multi_scanner_suite(
    target_url: str = "http://localhost:3000",
    container_target_url: Optional[str] = None,
    artifacts_dir: Optional[Path] = None,
    scanners: Optional[List[str]] = None,
    verify_connectivity: bool = True,
    run_id: Optional[str] = None,
    zap_filename: str = "zap-findings-live.json",
    nuclei_filename: str = "nuclei-findings-live.jsonl",
) -> Dict[str, Any]:
    """
    Pre-flight checks target and runs requested scanners (default: ['zap', 'nuclei']).
    Never silently substitutes sample findings on failure.
    """
    artifacts_dir = artifacts_dir or DEFAULT_ARTIFACTS_DIR
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    scanners = [s.strip().lower() for s in (scanners or ["zap", "nuclei"])]

    # Automatically map Windows-host loopback target to container address if not specified
    if not container_target_url:
        container_target_url = map_to_container_target(target_url)

    print("============================================================")
    print("Project Zero-Day: Multi-Scanner Automation Suite")
    print("============================================================")
    print(f"Run ID:                      {run_id or 'ad-hoc'}")
    print(f"Local Host Target:           {target_url}")
    print(f"Container Internal Target:   {container_target_url}")
    print(f"Artifacts Directory:         {artifacts_dir}")
    print(f"Active Scanners:             {', '.join(scanners)}")
    print("------------------------------------------------------------")

    # 1. Pre-flight Docker & Target Readiness
    docker_ok, docker_msg = check_docker_daemon()
    if not docker_ok:
        raise DockerConnectivityError(f"Pre-flight failed: {docker_msg}")
    print(f"[+] {docker_msg}")

    # Check host target reachability
    is_reachable, reach_msg = check_target_http(target_url=target_url)
    if not is_reachable:
        # If target is on port 3000 (Juice Shop default port), attempt to ensure container is running
        parsed_t = urllib.parse.urlparse(target_url)
        port = parsed_t.port or (443 if parsed_t.scheme == "https" else 80)
        if port == 3000:
            target_ok, target_msg = ensure_juice_shop_container(target_url=target_url)
            if not target_ok:
                raise TargetUnreachableError(f"Pre-flight failed: {target_msg}")
            reach_msg = target_msg
        else:
            raise TargetUnreachableError(
                f"Pre-flight failed: Target application at '{target_url}' is unreachable ({reach_msg}). "
                "Please verify your local application is running."
            )
    print(f"[+] {reach_msg}")

    # 2. Verify Docker container connectivity to the mapped target before scanning
    if verify_connectivity:
        conn_ok, conn_msg = verify_docker_container_connectivity(container_target_url)
        if not conn_ok:
            raise DockerConnectivityError(f"Pre-flight failed: {conn_msg}")
        print(f"[+] {conn_msg}")

    results: Dict[str, Any] = {}

    # 2. Run ZAP
    if "zap" in scanners:
        zap_meta = run_zap_baseline_scan(
            target_container_url=container_target_url,
            artifacts_dir=artifacts_dir,
            output_filename=zap_filename,
        )
        if run_id:
            zap_meta["run_id"] = run_id
        results["zap"] = zap_meta

    # 3. Run Nuclei
    if "nuclei" in scanners:
        nuclei_meta = run_nuclei_baseline_scan(
            target_container_url=container_target_url,
            artifacts_dir=artifacts_dir,
            output_filename=nuclei_filename,
        )
        if run_id:
            nuclei_meta["run_id"] = run_id
        results["nuclei"] = nuclei_meta

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Multi-Scanner Automation Manager")
    parser.add_argument("--target", default="http://localhost:3000", help="Target URL on host")
    parser.add_argument("--container-target", default=None, help="Target URL inside container (auto-mapped if omitted)")
    parser.add_argument("--scanners", default="zap,nuclei", help="Comma-separated list of scanners (zap, nuclei)")
    parser.add_argument("--artifacts-dir", default=str(DEFAULT_ARTIFACTS_DIR), help="Path to store scan artifacts")
    args = parser.parse_args()

    active_scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    res = run_multi_scanner_suite(
        target_url=args.target,
        container_target_url=args.container_target,
        artifacts_dir=Path(args.artifacts_dir),
        scanners=active_scanners,
    )
    print("\nScan Results Summary:")
    print(json.dumps(res, indent=2))
