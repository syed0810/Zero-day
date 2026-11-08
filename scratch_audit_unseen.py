#!/usr/bin/env python3
"""
Inspect out-of-class generalization (Setup B) and compare with baselines.
"""
from pathlib import Path
from collections import Counter
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
from train_decision_model import extract_all_training_records, VALID_ACTIONS

features, labels, _ = extract_all_training_records(Path("train.parquet"))
groups = [f["vulnerability_class"] for f in features]

gss = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42)
train_idx, test_idx = next(gss.split(features, labels, groups=groups))

X_train = [features[i] for i in train_idx]
y_train = [labels[i] for i in train_idx]
X_test = [features[i] for i in test_idx]
y_test = [labels[i] for i in test_idx]

train_classes = set([f["vulnerability_class"] for f in X_train])
test_classes = set([f["vulnerability_class"] for f in X_test])
print("Held-out test vulnerability classes count:", len(test_classes))
print("Held-out test vulnerability classes:", sorted(list(test_classes)))

pipe = Pipeline([
    ("vectorizer", DictVectorizer(sparse=True)),
    ("classifier", RandomForestClassifier(n_estimators=50, max_depth=16, min_samples_split=4, random_state=42, n_jobs=-1))
])
pipe.fit(X_train, y_train)
y_pred = pipe.predict(X_test)

plain_classes = list(VALID_ACTIONS)
print("\n--- Setup B: Out-of-Class Random Forest Detailed Report ---")
print(classification_report(y_test, y_pred, labels=plain_classes, zero_division=0))

# Baseline 1: Majority Class
dummy_maj = DummyClassifier(strategy="most_frequent")
dummy_maj.fit(X_train, y_train)
y_pred_maj = dummy_maj.predict(X_test)
print(f"Majority Class Baseline Accuracy: {accuracy_score(y_test, y_pred_maj)*100:.2f}% (Predicts: {dummy_maj.classes_[0]})")
print(f"Majority Class Macro-F1: {f1_score(y_test, y_pred_maj, average='macro', zero_division=0):.4f}")

# Baseline 2: Stratified
dummy_strat = DummyClassifier(strategy="stratified", random_state=42)
dummy_strat.fit(X_train, y_train)
y_pred_strat = dummy_strat.predict(X_test)
print(f"Stratified Random Baseline Accuracy: {accuracy_score(y_test, y_pred_strat)*100:.2f}%")
print(f"Stratified Random Macro-F1: {f1_score(y_test, y_pred_strat, average='macro', zero_division=0):.4f}")

# Check DictVectorizer behavior on unseen classes
vec = pipe.named_steps["vectorizer"]
sample_unseen = {"vulnerability_class": list(test_classes)[0]}
vec_out = vec.transform([sample_unseen])
print(f"\nDictVectorizer for unseen category '{list(test_classes)[0]}': non-zero elements = {vec_out.nnz}")
print(f"Total features in vectorizer: {len(vec.get_feature_names_out())}")

# Check test label distribution
print("\nTest Set Ground Truth Label Distribution:")
test_label_counts = Counter(y_test)
for k, v in test_label_counts.most_common():
    print(f"  {k:<26}: {v:>6} ({v/len(y_test)*100:.2f}%)")

# Check predictions distribution
print("\nTest Set Model Predictions Distribution:")
pred_counts = Counter(y_pred)
for k, v in pred_counts.most_common():
    print(f"  {k:<26}: {v:>6} ({v/len(y_pred)*100:.2f}%)")
