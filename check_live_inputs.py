#!/usr/bin/env python3
import json
from pathlib import Path
from policy_model import DecisionPolicyModel

with open("normalized_findings.json", "r", encoding="utf-8") as f:
    findings = json.load(f)

model = DecisionPolicyModel()
print(f"Total findings loaded from normalized_findings.json: {len(findings)}\n")

for i, f in enumerate(findings[:5]):
    feats = model.extract_features(f)
    print(f"Finding {i+1}:")
    print(f"  ID:            {f.get('id')}")
    print(f"  Title:         {f.get('title')}")
    print(f"  Risk Rating:   {f.get('risk_rating')}")
    print(f"  Values passed into model:")
    print(f"    - step_number:   {feats['step_number']}")
    print(f"    - total_steps:   {feats['total_steps']}")
    print(f"    - prior_action:  '{feats['prior_action']}'")
    print(f"    - current_phase: '{feats['current_phase']}'")
    print()
