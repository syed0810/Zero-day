# Project Zero-Day (ZERO//DAY)

**Project Zero-Day** is an automated, evidence-driven multi-scanner security analysis and triage pipeline designed for local web applications (such as OWASP Juice Shop). It bridges automated scanning, machine-learning-driven action policies, local retrieval-augmented generation (RAG), defensive verification probes, and standalone offline reporting.

---

## Architecture & Pipeline Stages

The pipeline executes through sequential, decoupled stages managed by the Master Orchestrator:

```
[Target: Local Web App]
         │
         ▼
[Stage 0: Multi-Scanner Suite] ──> OWASP ZAP & ProjectDiscovery Nuclei (Docker)
         │
         ▼
[Stage 1: Normalization & Deduplication] ──> Canonical Schema, Port Isolation, Corroboration
         │
         ▼
[Stage 2: Decision & Policy Engine] ──> Deterministic Triage (P1-P4) + Random Forest Classifier
         │
         ▼
[Stage 3: Scenario RAG & LLM Advisory] ──> SQLite FTS5 (pwn-scenarios) + Local Ollama Gemma
         │
         ▼
[Stage 4: Authoritative Policy Gate] ──> Strict Loopback & Port Scope Enforcement (ALLOW/DENY)
         │
         ▼
[Stage 5: Defensive Evidence Verification] ──> Read-Only HTTP Probes & Bounded Investigation Loop
         │
         ▼
[Stage 6: Offline Report Generation] ──> Self-Contained security_report.html & JSON Deliverables
```

### Stage Details

1. **Stage 0: Automated Multi-Scanner Execution (`app/scanner_manager.py`)**
   - Coordinates automated, non-destructive containerized scans using OWASP ZAP and ProjectDiscovery Nuclei.
   - Performs automated pre-flight Docker daemon checks, target reachability probes, and dynamic network address translation (`localhost` ↔ `host.docker.internal`).
   - Supports offline sample fixture execution (`--use-sample`).

2. **Stage 1: Normalization & Deduplication (`normalize_findings.py`, `app/nuclei_normalizer.py`, `app/finding_deduplicator.py`)**
   - Ingests raw scanner outputs (ZAP JSON/XML, Nuclei JSONL) into a unified Project Zero-Day canonical schema.
   - Canonicalizes targets while strictly preserving ports and paths.
   - Deduplicates findings across multi-scanner runs to avoid inflated vulnerability counts while preserving raw evidence.
   - Quarantines out-of-scope or mismatched target/port findings.

3. **Stage 2: Prioritization & Decision Engine (`decision_engine.py`, `policy_model.py`, `train_decision_model.py`)**
   - **Deterministic Priority Triage (P1–P4):** Authoritative operational mapping based on CWE, CVSS, and scanner risk ratings.
   - **Trained Policy Classifier (`policy_model.joblib`):** Random Forest model trained on 36,424 scenarios (~202K transitions) from `aeby/pwn-scenarios` with GroupShuffleSplit by vulnerability ID (zero data leakage) and SHA-256 integrity verification.
   - Selects bounded tactical actions: `collect_more_evidence`, `inspect_related_endpoint`, `verify_finding`, `recommend_remediation`, `manual_review`.

4. **Stage 3: Scenario RAG & LLM Advisory (`pz_scenarios.py`, `app/gemma_advisory.py`)**
   - High-speed contextual retrieval (<50ms) using SQLite FTS5 full-text search against `scenarios.db`.
   - Local Ollama LLM integration (`gemma:2b` / `gemma:7b`) for contextual security explanations, remediation advice, and risk summaries.
   - Non-authoritative advisory: LLM outputs are strictly informative and cannot override policy gates or calculated priorities.

5. **Stage 4: Authoritative Policy Gate (`app/target_validator.py`, PolicyGate)**
   - Enforces absolute control over execution scope.
   - Restricts scanning and probing strictly to authorized loopback targets (`localhost`, `127.0.0.1`, `::1`).
   - Reusable loopback policy allows arbitrary local ports while blocking unauthorized remote destinations, spoofed hosts, and redirect attacks.

6. **Stage 5: Defensive Evidence Verification & Investigation Loop (`app/verification_engine.py`, `app/investigation_loop.py`)**
   - Evaluates findings through a 4-state verification taxonomy:
     - `CONFIRMED`: Corroborated by reproducible defensive evidence (e.g., verified missing security headers).
     - `REJECTED`: Disproven by live response (e.g., header is present).
     - `NEEDS_VERIFICATION`: Insufficient evidence, offline fixture, or non-200 probe status (e.g., 404).
     - `MANUAL_REVIEW`: High-risk injection / code execution flaws (active attack payloads strictly prohibited).
   - Bounded autonomous investigation loop: Max 4 steps per finding, 50 requests total per run, rate-limited to ≥100ms.

7. **Stage 6: Interactive Report Dashboard (`app/report_generator.py`)**
   - Generates standalone, interactive `security_report.html` and structured `security_report.json`.
   - 100% offline compliant with zero external CDN dependencies (all styling, fonts, and scripts embedded).
   - Clearly marks data provenance (`LIVE SCAN` vs. `SAMPLE FIXTURE`).

---

## Safety & Defensive Invariants

- **No Active Exploitation:** The pipeline never launches intrusive exploits or injection payloads; injection vulnerabilities are safely routed to `MANUAL_REVIEW`.
- **Evidence Before Remediation:** Remediation actions are gated on verified defensive evidence.
- **Fail-Safe Policy Gate:** AI explanations and heuristic recommendations are strictly advisory; the Policy Gate retains final authorization authority.
- **Data Provenance Integrity:** Sample fixture outputs are strictly distinguished from live scanning telemetry.

---

## Repository Structure

```
.
├── app/
│   ├── finding_deduplicator.py     # Cross-scanner finding deduplication
│   ├── gemma_advisory.py           # Local Ollama Gemma advisory client
│   ├── investigation_loop.py       # Bounded multi-step investigation controller
│   ├── nuclei_normalizer.py        # Nuclei JSONL output parser and canonicalizer
│   ├── orchestrator.py             # Master pipeline orchestrator & PolicyGate
│   ├── report_generator.py         # Offline HTML/JSON security report generator
│   ├── scanner_manager.py          # Docker runner for ZAP & Nuclei
│   ├── target_validator.py         # Target validation, loopback checks & redirect safety
│   └── verification_engine.py      # Read-only defensive HTTP verification engine
├── artifacts/                      # Per-run scan results and raw findings
├── ablation_test.py                # Model ablation and feature importance tests
├── decision_engine.py              # Operational triage (P1-P4) & action heuristics
├── decision_log.json               # Authoritative policy decisions from latest run
├── normalize_findings.py           # OWASP ZAP finding normalizer
├── policy_model.joblib             # Trained Random Forest decision policy model
├── policy_model_metadata.json      # Model metadata, feature mapping & SHA-256 hash
├── policy_model.py                 # Decision policy inference engine
├── pz_scenarios.py                 # Scenario dataset RAG & SQLite FTS5 engine
├── requirements.txt                # Python core dependencies
├── scenarios.db                    # SQLite FTS5 database (~36.4K scenarios)
├── security_report.html            # Interactive standalone HTML dashboard
├── security_report.json            # Machine-readable report summary
├── train_decision_model.py         # Policy model training pipeline
├── train.parquet                   # Raw scenario dataset from HuggingFace
├── verification_results.json       # Verification engine evaluation log
└── test_*.py                       # Comprehensive test suites (87 tests)
```

---

## Installation & Setup

### Prerequisites

- **Python:** 3.10+ (tested on Python 3.14)
- **Docker Desktop:** (Optional) Required only for running live ZAP and Nuclei scans.
- **Ollama:** (Optional) Required only for live local LLM advisory (`gemma:2b` or similar).

### Install Dependencies

```bash
pip install -r requirements.txt
```

Core dependencies include:
- `scikit-learn` & `joblib`: Policy model training and inference
- `numpy` & `pyarrow`: Dataset processing and serialization
- `fpdf2`: PDF report support
- `pytest`: Test runner
- `requests`: Target verification and scanner probes

---

## Usage

### 1. Run the Full Orchestration Pipeline

**Run with offline sample fixture data (no Docker required):**
```bash
python app/orchestrator.py --use-sample
```

**Run against a live local target (e.g., OWASP Juice Shop on port 3000):**
```bash
python app/orchestrator.py --target http://localhost:3000
```

**Run against a custom local port and automatically open the HTML report:**
```bash
python app/orchestrator.py --target http://localhost:8000 --open-report
```

**Common CLI Options:**
- `--target URL`: Host-accessible target endpoint (default: `http://localhost:3000`).
- `--scope SCOPE`: Authorized scope URL pattern (defaults to local loopback policy).
- `--scanners LIST`: Comma-separated scanner list (`zap,nuclei` or individual scanners).
- `--use-sample`: Execute against sample fixture data without running live scanners.
- `--open-report`: Launch the default web browser to view the HTML report upon completion.
- `--ollama-timeout SEC`: Timeout for Ollama LLM queries (default: `90.0`).
- `--skip-reachability-check`: Skip initial target reachability probing.

### 2. Standalone Module Execution

- **Normalize ZAP findings:**
  ```bash
  python normalize_findings.py
  ```
- **Run Decision & Prioritization Engine:**
  ```bash
  python decision_engine.py
  ```
- **Query Scenario RAG (SQLite FTS5):**
  ```bash
  python pz_scenarios.py --query "sql injection"
  ```
- **Retrain the Policy Model:**
  ```bash
  python train_decision_model.py
  ```
- **Verify Model SHA-256 Integrity & Audit:**
  ```bash
  python verify_model_audit.py
  ```
- **Regenerate Reports from Findings:**
  ```bash
  python app/report_generator.py
  ```

---

## Testing

Run the test suite with `pytest`:

```bash
# Run all unit and integration tests
pytest

# Run specific test modules
pytest test_stage5_orchestration.py
pytest test_correctness_and_reliability_repairs.py
pytest test_decision_policy_model.py
```

The test suite covers:
- Target isolation, freshness, and port quarantine
- Multi-scanner normalization, URL canonicalization, and deduplication
- Policy model feature parity, SHA-256 integrity, and rule layers
- Defensive verification invariants (read-only probes, injection safety)
- Policy gate authorization and anti-bypass protections
- Offline HTML/JSON report consistency and data provenance integrity
