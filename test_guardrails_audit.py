#!/usr/bin/env python3
"""
Test all 5 defensive safeguards in policy_model.py and decision_engine.py.
Covers all 7 guardrail checks documented in the Project Zero-Day rubric.
"""
from pathlib import Path
import sys
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from policy_model import DecisionPolicyModel, VALID_ACTIONS


@pytest.fixture(scope="module")
def shared_model():
    model = DecisionPolicyModel()
    assert model.is_loaded, "Model failed to load"
    assert model.sha256_verified, "Model SHA-256 verification failed"
    return model


def test_guardrail_1_no_remediation_without_evidence(shared_model):
    """Guardrail 1: Critical SQLi in remediation_advisory phase with EMPTY evidence must not recommend remediation."""
    f_no_ev = {
        "title": "SQL Injection",
        "risk_rating": "Critical",
        "cwe_id": "CWE-89",
        "evidence": {},  # NO evidence
    }
    a1, c1 = shared_model.predict_action_with_confidence(f_no_ev, phase="remediation_advisory")
    assert a1 != "recommend_remediation", f"Expected action != recommend_remediation, got {a1}"
    assert a1 in VALID_ACTIONS, f"Action {a1} not in VALID_ACTIONS"


def test_guardrail_2_low_confidence_and_ood_handling(shared_model):
    """Guardrail 2: Novel vulnerability class, unknown source, unknown severity must escalate to manual_review with conf < 0.50."""
    f_ood = {
        "title": "Quantum Entanglement State Poisoning",
        "risk_rating": "Unknown",
        "source_type": "quantum_core",
        "cwe_id": "CWE-9999",
    }
    a2, c2 = shared_model.predict_action_with_confidence(f_ood)
    assert a2 == "manual_review", f"Expected manual_review for OOD finding, got {a2}"
    assert c2 < 0.50, f"Expected confidence < 0.50 for OOD finding, got {c2}"


def test_guardrail_3_failed_prior_action_escalation(shared_model):
    """Guardrail 3: High severity finding with prior_action_failed=True must escalate to manual_review."""
    f_failed = {
        "title": "Command Injection",
        "risk_rating": "High",
        "cwe_id": "CWE-78",
        "evidence": {"attack": "; id"},
    }
    a3, c3 = shared_model.predict_action_with_confidence(f_failed, prior_action_failed=True)
    assert a3 == "manual_review", f"Expected manual_review on failed prior action, got {a3}"


def test_guardrail_4_malformed_empty_dict(shared_model):
    """Guardrail 4a: Malformed input - empty dictionary must remain within VALID_ACTIONS."""
    act, conf = shared_model.predict_action_with_confidence({})
    assert act in VALID_ACTIONS, f"Action {act} not in VALID_ACTIONS"


def test_guardrail_5_malformed_arbitrary_keys(shared_model):
    """Guardrail 4b: Malformed input - arbitrary keys must remain within VALID_ACTIONS."""
    act, conf = shared_model.predict_action_with_confidence({"corrupted_key": [1, 2, 3]})
    assert act in VALID_ACTIONS, f"Action {act} not in VALID_ACTIONS"


def test_guardrail_6_malformed_none_values(shared_model):
    """Guardrail 4c: Malformed input - None values for core fields must remain within VALID_ACTIONS."""
    act, conf = shared_model.predict_action_with_confidence({"title": None, "risk_rating": None})
    assert act in VALID_ACTIONS, f"Action {act} not in VALID_ACTIONS"


def test_guardrail_7_zero_automatic_verification_invariant(shared_model):
    """Guardrail 5: Invariant - model action vocabulary cannot verify findings as true."""
    assert "verify_vulnerability_as_true" not in VALID_ACTIONS


def run_standalone_audit():
    model = DecisionPolicyModel()
    print(f"Model loaded: {model.is_loaded}")
    print(f"SHA-256 verified: {model.sha256_verified}")

    tests = []
    # Check 1
    f_no_ev = {"title": "SQL Injection", "risk_rating": "Critical", "cwe_id": "CWE-89", "evidence": {}}
    a1, c1 = model.predict_action_with_confidence(f_no_ev, phase="remediation_advisory")
    tests.append({
        "guardrail": "No remediation without evidence",
        "input_description": "Critical SQLi in remediation_advisory phase with EMPTY evidence",
        "actual_output": a1,
        "confidence": c1,
        "pass": (a1 != "recommend_remediation" and a1 in VALID_ACTIONS),
    })

    # Check 2
    f_ood = {"title": "Quantum Entanglement State Poisoning", "risk_rating": "Unknown", "source_type": "quantum_core", "cwe_id": "CWE-9999"}
    a2, c2 = model.predict_action_with_confidence(f_ood)
    tests.append({
        "guardrail": "Low-confidence & OOD handling",
        "input_description": "Novel vulnerability class, unknown source, unknown severity, CWE-9999",
        "actual_output": a2,
        "confidence": c2,
        "pass": (a2 == "manual_review" and c2 < 0.50),
    })

    # Check 3
    f_failed = {"title": "Command Injection", "risk_rating": "High", "cwe_id": "CWE-78", "evidence": {"attack": "; id"}}
    a3, c3 = model.predict_action_with_confidence(f_failed, prior_action_failed=True)
    tests.append({
        "guardrail": "Failed prior action escalation",
        "input_description": "High severity finding with prior_action_failed=True",
        "actual_output": a3,
        "confidence": c3,
        "pass": (a3 == "manual_review"),
    })

    # Checks 4, 5, 6
    malformed_inputs = [
        ({}, "Empty dictionary"),
        ({"corrupted_key": [1, 2, 3]}, "Malformed arbitrary keys"),
        ({"title": None, "risk_rating": None}, "None values for core fields"),
    ]
    for inp, desc in malformed_inputs:
        act, conf = model.predict_action_with_confidence(inp)
        tests.append({
            "guardrail": "Malformed / robust input confinement",
            "input_description": desc,
            "actual_output": act,
            "confidence": conf,
            "pass": (act in VALID_ACTIONS),
        })

    # Check 7
    tests.append({
        "guardrail": "Zero automatic verification invariant",
        "input_description": "Model action vocabulary limitation",
        "actual_output": "Actions confined to: " + str(VALID_ACTIONS),
        "confidence": 1.0,
        "pass": ("verify_vulnerability_as_true" not in VALID_ACTIONS),
    })

    print("\n--- Guardrail Verification Results ---")
    for t in tests:
        status = "PASS" if t["pass"] else "FAIL"
        print(f"[{status}] {t['guardrail']}: {t['input_description']}")
        print(f"       -> Action='{t['actual_output']}', Conf={t['confidence']:.2f}")


if __name__ == "__main__":
    run_standalone_audit()
