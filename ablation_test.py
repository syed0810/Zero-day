#!/usr/bin/env python3
"""
Project Zero-Day: Ablation Study Suite
Script: ablation_test.py
Objective: Evaluate RandomForest / DecisionTree across 4 experimental setups:
  Setup A: Current setup (baseline) - Grouped by vulnerability_id, all features, RandomForest
  Setup B: Grouped by vulnerability_class, all features, RandomForest
  Setup C: Grouped by vulnerability_class, NO trajectory features, RandomForest
  Setup D: Grouped by vulnerability_class, NO trajectory features, DecisionTreeClassifier(max_depth=3)
"""

import copy
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

PROJECT_ROOT = Path(__file__).resolve().parent
DATASET_FILE = PROJECT_ROOT / "train.parquet"

from train_decision_model import (
    SEVERITY_WEIGHT_MAP,
    VALID_ACTIONS,
    extract_all_training_records,
)

TRAJECTORY_KEYS = {"step_number", "total_steps", "step_ratio", "prior_action"}


def remove_trajectory_features(features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strip step_number, total_steps, step_ratio, and prior_action from feature dicts."""
    new_features = []
    for f in features:
        cleaned = {k: v for k, v in f.items() if k not in TRAJECTORY_KEYS}
        new_features.append(cleaned)
    return new_features


def run_experiment(
    name: str,
    features: List[Dict[str, Any]],
    labels: List[str],
    groups: List[str],
    classifier,
    random_seed: int = 42,
) -> Dict[str, Any]:
    print(f"\n{'='*70}")
    print(f"Running Experiment {name}")
    print(f"{'='*70}")
    unique_groups = len(set(groups))
    print(f"[*] Group count: {unique_groups} unique groups across {len(features):,} records")

    gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=random_seed)
    train_idx, test_idx = next(gss.split(features, labels, groups=groups))

    X_train = [features[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    train_groups = set([groups[i] for i in train_idx])

    X_test = [features[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]
    test_groups = set([groups[i] for i in test_idx])

    overlap = len(train_groups.intersection(test_groups))
    print(f"[*] Split: Train={len(X_train):,} records ({len(train_groups)} groups) | Test={len(X_test):,} records ({len(test_groups)} groups)")
    print(f"[*] Group overlap: {overlap} (leakage check)")

    # Build Pipeline
    pipe = Pipeline([
        ("vectorizer", DictVectorizer(sparse=True)),
        ("classifier", classifier),
    ])

    t0 = time.perf_counter()
    pipe.fit(X_train, y_train)
    train_time = time.perf_counter() - t0
    print(f"[+] Fitted model in {train_time:.2f}s")

    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    
    # Extract plain string classes
    classes_plain = [str(c) for c in pipe.classes_]
    # Ensure all VALID_ACTIONS are in confusion matrix labels for consistent alignment
    all_classes = list(VALID_ACTIONS)
    cm = confusion_matrix(y_test, y_pred, labels=all_classes)
    report = classification_report(y_test, y_pred, labels=all_classes, output_dict=True, zero_division=0)

    print(f"[+] Accuracy: {acc * 100:.2f}% | Macro-F1: {macro_f1:.4f}")

    return {
        "name": name,
        "train_records": len(X_train),
        "test_records": len(X_test),
        "train_groups": len(train_groups),
        "test_groups": len(test_groups),
        "accuracy": float(acc),
        "macro_f1": float(macro_f1),
        "classes": all_classes,
        "confusion_matrix": cm.tolist(),
        "report": report,
        "train_time_sec": round(train_time, 2),
    }


def main():
    print("==================================================================")
    print("Project Zero-Day: Comprehensive 4-Setup Model Ablation Study")
    print("==================================================================")

    # 1. Ingest full dataset records
    print("[*] Ingesting all 36,424 scenarios from train.parquet...")
    raw_features, labels, vuln_ids = extract_all_training_records(DATASET_FILE)
    print(f"[+] Total transitions: {len(raw_features):,}")

    # Vulnerability class groups
    vuln_class_groups = [f["vulnerability_class"] for f in raw_features]

    results = []

    # SETUP A: Current setup (baseline)
    # Split: vulnerability_id, Features: all, Model: RandomForest
    clf_rf_a = RandomForestClassifier(
        n_estimators=50,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1,
    )
    res_a = run_experiment(
        name="Setup A (Baseline: Vuln ID Split, All Features, RF)",
        features=raw_features,
        labels=labels,
        groups=vuln_ids,
        classifier=clf_rf_a,
    )
    results.append(res_a)

    # SETUP B: Grouped by vulnerability_class, all features, RandomForest
    clf_rf_b = RandomForestClassifier(
        n_estimators=50,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1,
    )
    res_b = run_experiment(
        name="Setup B (Vuln Class Split, All Features, RF)",
        features=raw_features,
        labels=labels,
        groups=vuln_class_groups,
        classifier=clf_rf_b,
    )
    results.append(res_b)

    # SETUP C: Grouped by vulnerability_class, NO trajectory features, RandomForest
    features_no_traj = remove_trajectory_features(raw_features)
    clf_rf_c = RandomForestClassifier(
        n_estimators=50,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1,
    )
    res_c = run_experiment(
        name="Setup C (Vuln Class Split, NO Trajectory Features, RF)",
        features=features_no_traj,
        labels=labels,
        groups=vuln_class_groups,
        classifier=clf_rf_c,
    )
    results.append(res_c)

    # SETUP D: Grouped by vulnerability_class, NO trajectory features, DecisionTreeClassifier(max_depth=3)
    clf_dt_d = DecisionTreeClassifier(
        max_depth=3,
        random_state=42,
    )
    res_d = run_experiment(
        name="Setup D (Vuln Class Split, NO Trajectory, DecisionTree max_depth=3)",
        features=features_no_traj,
        labels=labels,
        groups=vuln_class_groups,
        classifier=clf_dt_d,
    )
    results.append(res_d)

    # PRINT SUMMARY TABLE
    print("\n" + "=" * 90)
    print("                    ABLATION STUDY COMPARATIVE RESULTS")
    print("=" * 90)
    print(f"{'Setup':<50} | {'Accuracy':<10} | {'Macro-F1':<10} | {'Train Records':<13} | {'Test Records':<12}")
    print("-" * 105)
    for r in results:
        print(f"{r['name']:<50} | {r['accuracy']*100:>8.2f}% | {r['macro_f1']:>8.4f}   | {r['train_records']:>13,} | {r['test_records']:>12,}")

    # PRINT CONFUSION MATRICES
    print("\n" + "=" * 90)
    print("                    CONFUSION MATRICES BY SETUP")
    print("=" * 90)
    classes = VALID_ACTIONS
    header = f"{'True \\ Pred':<26}" + "".join([f"{c[:6]:>9}" for c in classes])
    for r in results:
        print(f"\n--- {r['name']} ---")
        print(header)
        cm = r["confusion_matrix"]
        for idx, c in enumerate(classes):
            row_str = "".join([f"{val:>9}" for val in cm[idx]])
            print(f"{c:<26}{row_str}")

    return results


if __name__ == "__main__":
    main()
