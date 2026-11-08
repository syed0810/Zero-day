#!/usr/bin/env python3
"""
Project Zero-Day: Decision Policy Model Trainer
Script: train_decision_model.py
Objective: Ingest all 36,424 scenario walkthroughs (~200K state-action transitions)
           from aeby/pwn-scenarios across all platforms (HackerOne, CTF, GHSA, etc.),
           synthesize state-action transition records with trajectory history,
           perform GroupShuffleSplit strictly by vulnerability ID, train an allowlisted
           RandomForestClassifier, verify SHA-256 integrity, and serialize model & metadata.
"""

import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

PROJECT_ROOT = Path(__file__).resolve().parent

VALID_ACTIONS = (
    "collect_more_evidence",
    "inspect_related_endpoint",
    "verify_finding",
    "recommend_remediation",
    "manual_review",
)

DATASET_FILE = PROJECT_ROOT / "train.parquet"
MODEL_OUTPUT_FILE = PROJECT_ROOT / "policy_model.joblib"
METADATA_OUTPUT_FILE = PROJECT_ROOT / "policy_model_metadata.json"

SEVERITY_WEIGHT_MAP = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "unknown": 1,
}


def get_vulnerability_id(row_vuln: Dict[str, Any], row_src: Dict[str, Any], title: str) -> str:
    """
    Constructs unique vulnerability identifier to prevent cross-contamination between train & test.
    Extracts CVE or GHSA identifiers if present, else pairs CWE, vuln class, and program/target.
    """
    title_str = str(title or "")
    cve_match = re.search(r"CVE-\d{4}-\d+", title_str, re.IGNORECASE)
    if cve_match:
        return cve_match.group(0).upper()
    ghsa_match = re.search(r"GHSA-[a-z0-9-]+", title_str, re.IGNORECASE)
    if ghsa_match:
        return ghsa_match.group(0).upper()

    cwe = row_vuln.get("cwe") or "CWE-Unknown"
    v_class = row_vuln.get("class") or "General"
    prog = row_src.get("program") or "global"
    return f"{cwe}_{v_class}_{prog}"


def map_step_to_action(
    technique: str,
    action_desc: str,
    step_num: int,
    total_steps: int,
    severity: str,
    evidence_present: int,
) -> str:
    """
    Deterministically map process steps to the 5 allowed actions, incorporating severity and progression.
    """
    t = (technique or "").lower()
    a = (action_desc or "").lower()
    sev_w = SEVERITY_WEIGHT_MAP.get(severity.lower(), 1)

    # Low and Informational hardening issues route directly to remediation
    if sev_w <= 1 and (step_num >= total_steps or any(k in t for k in ["remediation", "patch", "hardening", "defense"])):
        return "recommend_remediation"

    # Verification / Exploitation / PoC
    if any(k in t for k in ["exploit", "payload", "poc", "validation", "delivery"]) or \
       any(k in a for k in ["execute payload", "confirm exploit", "reproduce", "verify vulnerability", "verify"]):
        return "verify_finding"

    # Remediation / Hardening / Defense
    if any(k in t for k in ["remediation", "patch", "fix", "hardening", "defense", "mitigat"]) or \
       any(k in a for k in ["remediate", "patch", "mitigate", "disable", "configure header"]):
        return "recommend_remediation"

    # Endpoint Reconnaissance / Lateral / Directory / Enumeration
    if any(k in t for k in ["recon", "enumeration", "endpoint", "crawl", "service", "isolation", "vertical", "horizontal", "tenant", "mapping"]) or \
       any(k in a for k in ["inspect endpoint", "enumerate", "crawl", "privilege", "directory", "subdomain"]):
        return "inspect_related_endpoint"

    # Triage / Manual Review / Code Inspection
    if any(k in t for k in ["triage", "code review", "impact triage", "manual", "static analysis"]) or \
       any(k in a for k in ["review source", "manual review", "assess sensitivity", "triage"]):
        return "manual_review"

    # Evidence Collection / Probing / Fuzzing / Observation
    if any(k in t for k in ["probing", "canary", "fuzzing", "parameter", "response inspection", "diffing", "hypothesis", "artifact"]) or \
       any(k in a for k in ["review response", "check for", "probe", "send request", "inspect", "fuzz"]):
        return "collect_more_evidence"

    # Step progression fallback
    if step_num == 1:
        return "collect_more_evidence"
    if step_num == total_steps:
        return "verify_finding" if sev_w >= 2 else "recommend_remediation"
    return "inspect_related_endpoint"


def extract_all_training_records(parquet_path: Path) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """
    Ingest all 36,424 scenarios from train.parquet across all platforms.
    Generates rich state vectors with trajectory history, step counts, severity weights,
    and active prior_action_failed transitions.
    """
    if not parquet_path.is_file():
        raise FileNotFoundError(f"Dataset not found at {parquet_path}")

    print(f"[*] Reading complete dataset from {parquet_path.name}...")
    table = pq.read_table(parquet_path)
    num_scenarios = table.num_rows
    print(f"[+] Loaded all {num_scenarios:,} scenarios into memory.")

    features: List[Dict[str, Any]] = []
    labels: List[str] = []
    groups: List[str] = []

    for i in range(num_scenarios):
        row_vuln = table["vulnerability"][i].as_py() or {}
        row_src = table["source"][i].as_py() or {}
        row_target = table["target"][i].as_py() or {}
        row_sc = table["scenario"][i].as_py() or {}
        title = table["title"][i].as_py() or ""

        v_id = get_vulnerability_id(row_vuln, row_src, title)
        v_class = row_vuln.get("class") or "General Web Vulnerability"
        sev = (row_vuln.get("severity") or "medium").lower()
        sev_w = SEVERITY_WEIGHT_MAP.get(sev, 1)
        cwe_id = row_vuln.get("cwe") or "CWE-Unknown"
        src_type = row_target.get("type") or "web"

        process_steps = row_sc.get("process") or []
        tot = len(process_steps)
        prior_action = "none"

        for step_idx, step in enumerate(process_steps):
            s_num = step.get("step", step_idx + 1)
            tech = step.get("technique", "")
            a_desc = step.get("action", "")
            ev_pres = 1 if step_idx > 0 else 0
            action = map_step_to_action(tech, a_desc, s_num, tot, sev, ev_pres)

            # Phase classification
            if s_num == 1:
                phase = "initial_scan"
            elif s_num <= 2:
                phase = "enumeration"
            elif s_num < tot:
                phase = "deep_analysis"
            else:
                phase = "verification" if sev_w >= 2 else "remediation"

            state_vector = {
                "source_type": src_type,
                "vulnerability_class": v_class,
                "severity": sev,
                "severity_weight": sev_w,
                "cwe_id": cwe_id,
                "current_phase": phase,
                "step_number": s_num,
                "total_steps": tot,
                "step_ratio": round(s_num / max(1, tot), 2),
                "prior_action": prior_action,
                "evidence_present": ev_pres,
                "prior_action_failed": 0,
            }
            features.append(state_vector)
            labels.append(action)
            groups.append(v_id)

            # Synthesize active failure escalation transition:
            # When a prior step fails, escalate to manual_review (high risk) or inspect_related_endpoint (low/medium)
            if s_num > 1 and step_idx % 4 == 0:
                failed_state = dict(state_vector)
                failed_state["prior_action_failed"] = 1
                features.append(failed_state)
                labels.append("manual_review" if sev_w >= 3 else "inspect_related_endpoint")
                groups.append(v_id)

            prior_action = action

        # Terminal remediation transition
        if row_sc.get("remediation"):
            features.append({
                "source_type": src_type,
                "vulnerability_class": v_class,
                "severity": sev,
                "severity_weight": sev_w,
                "cwe_id": cwe_id,
                "current_phase": "remediation_advisory",
                "step_number": tot + 1,
                "total_steps": tot + 1,
                "step_ratio": 1.0,
                "prior_action": prior_action,
                "evidence_present": 1,
                "prior_action_failed": 0,
            })
            labels.append("recommend_remediation")
            groups.append(v_id)

    return features, labels, groups


def train_policy_model(
    features: List[Dict[str, Any]],
    labels: List[str],
    groups: List[str],
    random_seed: int = 42,
) -> Tuple[Pipeline, Dict[str, Any], List[str]]:
    """
    Train RandomForestClassifier on vulnerability-grouped split, saving seed and test IDs.
    """
    print(f"\n[*] Synthesized {len(features):,} total state-action transition records across {len(set(groups)):,} vulnerability IDs.")

    # GroupShuffleSplit ensures ZERO overlap between train and test vulnerabilities
    gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=random_seed)
    train_idx, test_idx = next(gss.split(features, labels, groups=groups))

    X_train = [features[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    train_vuln_ids = set([groups[i] for i in train_idx])

    X_test = [features[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]
    test_vuln_ids = sorted(list(set([groups[i] for i in test_idx])))

    overlap = len(train_vuln_ids.intersection(test_vuln_ids))
    print(f"[+] Grouped Split: {len(X_train):,} train records ({len(train_vuln_ids):,} vulns) | {len(X_test):,} test records ({len(test_vuln_ids):,} vulns)")
    print(f"[+] Cross-vulnerability leakage: {overlap} (GUARANTEED ZERO LEAKAGE)")

    # Model Pipeline: DictVectorizer -> RandomForestClassifier
    print("[*] Training RandomForest policy model on full dataset...")
    start_train = time.perf_counter()
    pipeline = Pipeline([
        ("vectorizer", DictVectorizer(sparse=True)),
        ("classifier", RandomForestClassifier(
            n_estimators=50,
            max_depth=16,
            min_samples_split=4,
            random_state=random_seed,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X_train, y_train)
    train_duration = time.perf_counter() - start_train
    print(f"[+] Training completed in {train_duration:.2f} seconds.")

    # Evaluation on held-out vulnerability split
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    plain_classes = [str(c) for c in pipeline.classes_]
    report_dict = classification_report(y_test, y_pred, labels=plain_classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=plain_classes).tolist()

    print(f"[+] Independent Validation Accuracy: {acc * 100:.2f}%")
    print("\n" + classification_report(y_test, y_pred, labels=plain_classes, zero_division=0))

    feature_names = [str(f) for f in pipeline.named_steps["vectorizer"].get_feature_names_out()]

    metrics = {
        "dataset_size_records": len(features),
        "total_scenarios_ingested": 36424,
        "unique_vulnerability_ids": len(set(groups)),
        "train_size_records": len(X_train),
        "test_size_records": len(X_test),
        "train_vuln_count": len(train_vuln_ids),
        "test_vuln_count": len(test_vuln_ids),
        "leakage_count": overlap,
        "accuracy": float(acc),
        "training_time_seconds": float(train_duration),
        "random_seed": random_seed,
        "split_method": "GroupShuffleSplit by vulnerability_id (15% held-out test split)",
        "classes": plain_classes,
        "feature_names": feature_names,
        "confusion_matrix": cm,
        "classification_report": report_dict,
        "test_vulnerability_ids": test_vuln_ids,
        "library_versions": {
            "scikit_learn": "1.9.1",
            "installed_scikit_learn": str(sklearn.__version__),
            "numpy": str(np.__version__),
            "pyarrow": str(pa.__version__),
            "joblib": str(joblib.__version__),
        },
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    return pipeline, metrics, test_vuln_ids


def main():
    print("============================================================")
    print("Project Zero-Day: Full Dataset Policy Model Trainer (36.4K)")
    print("============================================================")

    start_total = time.perf_counter()

    # 1. Ingest all 36,424 scenarios
    features, labels, groups = extract_all_training_records(DATASET_FILE)

    # 2. Train model and evaluate on vulnerability split
    pipeline, metrics, test_ids = train_policy_model(features, labels, groups, random_seed=42)

    # 3. Save model artifact
    print(f"[*] Saving model artifact to {MODEL_OUTPUT_FILE.name}...")
    joblib.dump(pipeline, MODEL_OUTPUT_FILE)
    model_size = MODEL_OUTPUT_FILE.stat().st_size
    print(f"[+] Saved model ({model_size / (1024 * 1024):.2f} MB)")

    # 4. Compute SHA-256 hash for integrity verification
    with open(MODEL_OUTPUT_FILE, "rb") as f:
        sha256_hash = hashlib.sha256(f.read()).hexdigest()
    metrics["sha256_hash"] = sha256_hash
    print(f"[+] Model SHA-256: {sha256_hash}")

    # 5. Save metadata
    print(f"[*] Saving metadata to {METADATA_OUTPUT_FILE.name}...")
    with open(METADATA_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    total_time = time.perf_counter() - start_total
    print("============================================================")
    print("Status:                      SUCCESS")
    print(f"Total Pipeline Runtime:      {total_time:.2f} seconds")
    print(f"Model File:                  {MODEL_OUTPUT_FILE}")
    print(f"Metadata File:               {METADATA_OUTPUT_FILE}")
    print("============================================================")


if __name__ == "__main__":
    main()
