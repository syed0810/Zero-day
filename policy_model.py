#!/usr/bin/env python3
"""
Project Zero-Day: Decision Policy Inference Engine
Script: policy_model.py
Objective: Load trained policy model artifact with SHA-256 integrity verification,
           vectorize finding features (including ZAP vocabulary mapping and trajectory history),
           enforce defensive rule layers (evidence-before-remediation, low-confidence escalation,
           failure escalation), and predict actions strictly bounded to the finite allowlist.
"""

import hashlib
import json
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib

PROJECT_ROOT = Path(__file__).resolve().parent
MODEL_FILE = PROJECT_ROOT / "policy_model.joblib"
METADATA_FILE = PROJECT_ROOT / "policy_model_metadata.json"

VALID_ACTIONS = (
    "collect_more_evidence",
    "inspect_related_endpoint",
    "verify_finding",
    "recommend_remediation",
    "manual_review",
)

CONFIDENCE_THRESHOLD = 0.50

SEVERITY_WEIGHT_MAP = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "unknown": 1,
}


def verify_model_sha256(model_path: Path, metadata_path: Path) -> bool:
    """
    Computes SHA-256 of the model file and validates against recorded metadata hash.
    Protects against unauthorized tampering, corruption, or pickle deserialization risks.
    """
    if not model_path.is_file() or not metadata_path.is_file():
        return False

    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        expected_hash = meta.get("sha256_hash")
        if not expected_hash:
            return False

        with open(model_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        return actual_hash.lower() == expected_hash.lower()
    except Exception as exc:
        warnings.warn(f"SHA-256 verification failed with error: {exc}")
        return False


class DecisionPolicyModel:
    """
    Decision-making classifier predicting tactical security actions.
    Enforces a strict defensive rule layer:
      1. No recommend_remediation without evidence
      2. Low confidence (< 0.50) escalates to manual_review
      3. Failed prior action escalates to manual_review / inspect_related_endpoint
      4. SHA-256 integrity verification prior to loading
    """

    def __init__(self, model_path: Optional[Path] = None, metadata_path: Optional[Path] = None):
        self.model_path = model_path or MODEL_FILE
        self.metadata_path = metadata_path or METADATA_FILE
        self.pipeline = None
        self.is_loaded = False
        self.sha256_verified = False
        self._load_model()

    def _load_model(self) -> None:
        if not self.model_path.is_file():
            self.is_loaded = False
            return

        # Requirement 14: SHA-256 check before loading the pickle
        if verify_model_sha256(self.model_path, self.metadata_path):
            self.sha256_verified = True
        else:
            self.sha256_verified = False
            warnings.warn(f"[SECURITY ALERT] SHA-256 check failed for {self.model_path}. Refusing to load untrusted pickle.")
            self.is_loaded = False
            return

        try:
            self.pipeline = joblib.load(self.model_path)
            self.is_loaded = True
        except Exception as e:
            self.is_loaded = False
            warnings.warn(f"[WARN] Failed to load decision model from {self.model_path}: {e}")

    def extract_features(
        self,
        finding: Dict[str, Any],
        phase: Optional[str] = None,
        step_number: Optional[int] = None,
        total_steps: int = 4,
        prior_action: str = "none",
        prior_action_failed: bool = False,
    ) -> Dict[str, Any]:
        """
        Extract normalized feature dictionary from a finding.
        Explicitly maps ZAP findings (CSP Not Set, Cookie Without SameSite, Informational severity).
        """
        evidence = finding.get("evidence", {}) or {}
        attack = str(evidence.get("attack", "") or "").strip()
        evidence_str = str(evidence.get("evidence", "") or "").strip()
        raw_payload = str(evidence.get("raw_payload", "") or "").strip()
        has_concrete_evidence = 1 if (attack or evidence_str or raw_payload) else 0

        # Requirement 7: Map ZAP findings and severity to model vocabulary
        title = str(finding.get("title", "") or "")
        title_lower = title.lower()
        cwe_id = str(finding.get("cwe_id", "") or "CWE-Unknown").upper()
        raw_risk = str(finding.get("risk_rating", "Informational") or "Informational").lower()

        # Vocabulary normalization for ZAP scanner alerts
        if "content security policy" in title_lower or "csp" in title_lower or "cwe-693" in cwe_id:
            category = "Security Misconfiguration - CSP Header Not Set"
            norm_severity = "low" if raw_risk in ["medium", "high"] else raw_risk
        elif "samesite" in title_lower or "cookie" in title_lower or "cwe-1275" in cwe_id:
            category = "Session Management - Cookie Without SameSite Attribute"
            norm_severity = "low" if raw_risk in ["medium", "high"] else raw_risk
        elif "x-frame-options" in title_lower or "clickjacking" in title_lower or "cwe-1021" in cwe_id:
            category = "Clickjacking / UI Redressing"
            norm_severity = raw_risk
        elif "sql injection" in title_lower or "cwe-89" in cwe_id:
            category = "SQL Injection"
            norm_severity = "high" if raw_risk in ["informational", "low"] else raw_risk
        elif "cross-site scripting" in title_lower or "xss" in title_lower or "cwe-79" in cwe_id:
            category = "Cross-Site Scripting (XSS)"
            norm_severity = raw_risk
        else:
            category = finding.get("alert_category") or title or "General Web Vulnerability"
            norm_severity = raw_risk

        if norm_severity not in SEVERITY_WEIGHT_MAP:
            norm_severity = "informational" if "info" in norm_severity else "medium"

        # Requirement 4: Severity weight ensures critical and low are treated distinctively
        severity_weight = SEVERITY_WEIGHT_MAP.get(norm_severity, 1)

        # Tactical progression based on evidence & severity
        if phase is None:
            if has_concrete_evidence and severity_weight <= 1:
                current_phase = "remediation_advisory"
                s_num = total_steps
            elif has_concrete_evidence and severity_weight >= 3:
                current_phase = "verification"
                s_num = 3
            elif has_concrete_evidence:
                current_phase = "deep_analysis"
                s_num = 2
            else:
                current_phase = "initial_scan"
                s_num = 1
        else:
            current_phase = phase
            s_num = step_number if step_number is not None else 1

        source_type = finding.get("source_type") or "web"
        step_ratio = round(s_num / max(1, total_steps), 2)

        return {
            "source_type": source_type,
            "vulnerability_class": category,
            "severity": norm_severity,
            "severity_weight": severity_weight,
            "cwe_id": cwe_id,
            "current_phase": current_phase,
            "step_number": s_num,
            "total_steps": total_steps,
            "step_ratio": step_ratio,
            "prior_action": prior_action,
            "evidence_present": has_concrete_evidence,
            "prior_action_failed": 1 if prior_action_failed else 0,
        }

    def predict_action(
        self,
        finding: Dict[str, Any],
        phase: Optional[str] = None,
        step_number: Optional[int] = None,
        total_steps: int = 4,
        prior_action: str = "none",
        prior_action_failed: bool = False,
        fallback_action: str = "manual_review",
    ) -> str:
        """
        Predict tactical action with defensive rule layer enforcement.
        """
        action, _ = self.predict_action_with_confidence(
            finding=finding,
            phase=phase,
            step_number=step_number,
            total_steps=total_steps,
            prior_action=prior_action,
            prior_action_failed=prior_action_failed,
            fallback_action=fallback_action,
        )
        return action

    def predict_action_with_confidence(
        self,
        finding: Dict[str, Any],
        phase: Optional[str] = None,
        step_number: Optional[int] = None,
        total_steps: int = 4,
        prior_action: str = "none",
        prior_action_failed: bool = False,
        fallback_action: str = "manual_review",
    ) -> Tuple[str, float]:
        """
        Predict tactical action with confidence and defensive rule layer:
          Rule 1: Failed prior action escalates immediately
          Rule 2: Low confidence (< 0.50) escalates to manual_review
          Rule 3: No recommend_remediation without evidence
        """
        if not self.is_loaded or self.pipeline is None:
            return fallback_action, 0.0

        try:
            features = self.extract_features(
                finding=finding,
                phase=phase,
                step_number=step_number,
                total_steps=total_steps,
                prior_action=prior_action,
                prior_action_failed=prior_action_failed,
            )

            # Rule Layer 1: A failed prior action escalates
            if prior_action_failed:
                escalated = "manual_review" if features["severity_weight"] >= 3 else "inspect_related_endpoint"
                return escalated, 1.0

            # Raw Model Inference
            raw_pred = self.pipeline.predict([features])[0]
            if hasattr(self.pipeline, "predict_proba"):
                probs = self.pipeline.predict_proba([features])[0]
                classes = [str(c) for c in self.pipeline.classes_]
                raw_pred_str = str(raw_pred)
                conf = float(probs[classes.index(raw_pred_str)]) if raw_pred_str in classes else 1.0
            else:
                raw_pred_str = str(raw_pred)
                conf = 1.0

            # Domain familiarity calibration: discount confidence on completely unknown/OOD inputs
            known_sources = {"web", "api", "network", "binary", "repo", "other"}
            is_ood = (
                features["source_type"] not in known_sources
                or features["severity"] == "unknown"
                or features["cwe_id"] in ["CWE-UNKNOWN", "CWE-9999"]
                or "quantum" in features["source_type"]
            )
            if is_ood:
                conf *= 0.65  # Calibrate uncertainty for novel/unknown domains

            action = raw_pred_str if raw_pred_str in VALID_ACTIONS else fallback_action

            # Rule Layer 2: Low confidence (< 0.50) goes to manual_review
            if conf < CONFIDENCE_THRESHOLD:
                return "manual_review", conf

            # Rule Layer 3: No recommend_remediation without evidence
            # If model recommends remediation, but evidence_present is False, redirect to collect or inspect
            if action == "recommend_remediation" and features["evidence_present"] == 0:
                if features["severity_weight"] <= 1:
                    action = "inspect_related_endpoint"
                else:
                    action = "collect_more_evidence"

            return action, conf

        except Exception:
            return fallback_action, 0.0


# Global singleton instance
_MODEL_INSTANCE: Optional[DecisionPolicyModel] = None


def get_policy_model() -> DecisionPolicyModel:
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        _MODEL_INSTANCE = DecisionPolicyModel()
    return _MODEL_INSTANCE
