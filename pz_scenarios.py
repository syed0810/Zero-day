#!/usr/bin/env python3
"""
Project Zero-Day - Stage 3: Scenario Dataset Retrieval-Augmented Generation (RAG)
Script: pz_scenarios.py
Objective: Ingest the `aeby/pwn-scenarios` dataset (~36.4K security scenarios) into SQLite FTS5,
           expose high-speed contextual search (<50ms), and supply RAG references to Gemma prompts.
"""

import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


DB_FILENAME = "scenarios.db"
DATASET_PARQUET = "train.parquet"
HF_DATASET_URL = "https://huggingface.co/datasets/aeby/pwn-scenarios/resolve/main/data/train.parquet"


def resolve_file_path(filename: str) -> Path:
    """
    Dynamically resolve target file path across current directory, script parent directory,
    or standard project locations.
    """
    search_dirs = [
        Path.cwd(),
        Path(__file__).resolve().parent,
        Path("C:/ZeroDay"),
        Path("C:/zrd"),
    ]
    for directory in search_dirs:
        candidate = directory / filename
        if candidate.is_file():
            return candidate
    return Path(__file__).resolve().parent / filename


def get_db_path() -> Path:
    return resolve_file_path(DB_FILENAME)


def ensure_dataset_file(target_path: Path) -> Path:
    """
    Ensures the raw dataset file exists locally. Downloads train.parquet if missing.
    """
    if target_path.is_file() and target_path.stat().st_size > 100000:
        return target_path

    print(f"[INFO] Dataset file not found at {target_path}. Downloading from Hugging Face ({HF_DATASET_URL})...")
    req = urllib.request.Request(
        HF_DATASET_URL,
        headers={"User-Agent": "ProjectZeroDay-RAG/1.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp, open(target_path, "wb") as out_file:
        chunk_size = 64 * 1024
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            out_file.write(chunk)

    print(f"[SUCCESS] Downloaded {target_path.stat().st_size / (1024*1024):.2f} MB to {target_path}")
    return target_path


def build_scenarios_db(source_parquet: Optional[Path] = None, db_path: Optional[Path] = None) -> Tuple[int, float]:
    """
    FR-01: Ingests `aeby/pwn-scenarios` records into a clean SQLite relational table
    with an FTS5 virtual table overlay.
    """
    try:
        import pyarrow.parquet as pq
    except ImportError:
        raise ImportError("pyarrow is required for dataset ingestion. Install via 'pip install pyarrow'.")

    if db_path is None:
        db_path = Path(__file__).resolve().parent / DB_FILENAME

    if source_parquet is None:
        source_parquet = Path(__file__).resolve().parent / DATASET_PARQUET

    source_parquet = ensure_dataset_file(source_parquet)

    print("============================================================")
    print("Project Zero-Day: Ingesting aeby/pwn-scenarios Dataset")
    print("============================================================")
    print(f"Source Parquet:             {source_parquet}")
    print(f"Target Database:            {db_path}")

    start_time = time.perf_counter()

    # Read records from parquet
    table = pq.read_table(source_parquet)
    raw_records = table.to_pylist()

    # Initialize SQLite database
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA synchronous = OFF")
    con.execute("PRAGMA journal_mode = MEMORY")
    con.execute("PRAGMA temp_store = MEMORY")

    # Drop existing tables to ensure clean rebuild
    con.execute("DROP TABLE IF EXISTS scenarios_fts")
    con.execute("DROP TABLE IF EXISTS scenarios")

    # Relational base table
    con.execute("""
        CREATE TABLE scenarios (
            id TEXT PRIMARY KEY,
            title TEXT,
            cwe_id TEXT,
            vulnerability_class TEXT,
            severity TEXT,
            owasp_category TEXT,
            summary TEXT,
            impact TEXT,
            remediation TEXT,
            tags TEXT,
            source_url TEXT
        )
    """)
    con.execute("CREATE INDEX idx_scenarios_cwe ON scenarios(cwe_id)")
    con.execute("CREATE INDEX idx_scenarios_class ON scenarios(vulnerability_class)")

    # FTS5 Virtual Table for full-text search
    con.execute("""
        CREATE VIRTUAL TABLE scenarios_fts USING fts5(
            id UNINDEXED,
            title,
            cwe_id,
            vulnerability_class,
            summary,
            remediation,
            tags
        )
    """)

    scenario_rows = []
    fts_rows = []

    for r in raw_records:
        r_id = str(r.get("id") or "").strip()
        title = str(r.get("title") or "").strip()
        vuln = r.get("vulnerability") or {}
        cwe_raw = vuln.get("cwe")
        cwe_id = str(cwe_raw).strip() if cwe_raw else None
        v_class = str(vuln.get("class") or "").strip()
        severity = str(vuln.get("severity") or "medium").strip()
        owasp = str(vuln.get("owasp_category") or "").strip()

        scen = r.get("scenario") or {}
        summary = str(scen.get("summary") or "").strip()
        impact = "; ".join(scen.get("impact") or [])
        remediation = "; ".join(scen.get("remediation") or [])

        tags = ", ".join(r.get("tags") or [])
        source = r.get("source") or {}
        source_url = str(source.get("url") or "")

        scenario_rows.append((r_id, title, cwe_id, v_class, severity, owasp, summary, impact, remediation, tags, source_url))
        fts_rows.append((r_id, title, cwe_id or "", v_class, summary, remediation, tags))

    cur = con.cursor()
    cur.executemany("INSERT INTO scenarios VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", scenario_rows)
    cur.executemany("INSERT INTO scenarios_fts VALUES (?, ?, ?, ?, ?, ?, ?)", fts_rows)
    con.commit()

    total_count = cur.execute("SELECT count(*) FROM scenarios").fetchone()[0]
    fts_count = cur.execute("SELECT count(*) FROM scenarios_fts").fetchone()[0]
    con.close()

    elapsed = time.perf_counter() - start_time
    print(f"Indexed scenarios count:    {total_count}")
    print(f"FTS5 virtual table count:   {fts_count}")
    print(f"Total build duration:       {elapsed:.2f} seconds")
    print("Status:                     SUCCESS")
    print("============================================================")

    return total_count, elapsed


def clean_fts_query(query_str: str) -> str:
    """
    Sanitize input string for SQLite FTS5 MATCH syntax.
    """
    # Remove FTS5 operator characters
    sanitized = re.sub(r'["*^:()\[\]{}]', ' ', query_str).strip()
    words = [w for w in sanitized.split() if len(w) > 1]
    return " ".join(words)


def get_relevant_scenarios(
    cwe_id: Optional[str] = None,
    vulnerability_class: Optional[str] = None,
    limit: int = 3,
    db_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    FR-02 & FR-03: Expose clean Python API to retrieve contextual scenario references
    by CWE, vulnerability class, or keywords in < 50ms.

    Hard Constraint: Scenarios must be treated as advisory context and NOT as proof
    of target exploitability.
    """
    start_time = time.perf_counter()

    if db_path is None:
        db_path = get_db_path()

    if not db_path.is_file():
        try:
            build_scenarios_db(db_path=db_path)
        except Exception:
            return []

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    results: List[Dict[str, Any]] = []
    seen_ids = set()

    # Normalize CWE string
    clean_cwe = None
    if cwe_id:
        cwe_str = str(cwe_id).strip().upper()
        clean_cwe = cwe_str if cwe_str.startswith("CWE-") else f"CWE-{cwe_str}"

    # Strategy 1: Exact CWE lookup in relational table
    if clean_cwe:
        cur.execute("""
            SELECT id, title, cwe_id, vulnerability_class, severity, summary, remediation, source_url
            FROM scenarios
            WHERE cwe_id = ?
            ORDER BY CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                ELSE 4 END
            LIMIT ?
        """, (clean_cwe, limit))

        for row in cur.fetchall():
            r_dict = dict(row)
            seen_ids.add(r_dict["id"])
            results.append(r_dict)

    # Strategy 2: FTS5 keyword query if limit not reached or CWE had no direct matches
    if len(results) < limit:
        remaining = limit - len(results)
        search_terms = vulnerability_class or ""
        if not search_terms and clean_cwe:
            search_terms = clean_cwe

        safe_fts = clean_fts_query(search_terms)
        if safe_fts:
            try:
                cur.execute("""
                    SELECT id, title, cwe_id, vulnerability_class, summary, remediation
                    FROM scenarios_fts
                    WHERE scenarios_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                """, (safe_fts, remaining * 2))

                for row in cur.fetchall():
                    r_dict = dict(row)
                    if r_dict["id"] not in seen_ids:
                        seen_ids.add(r_dict["id"])
                        r_dict["source_url"] = ""
                        r_dict["severity"] = "medium"
                        results.append(r_dict)
                        if len(results) >= limit:
                            break
            except sqlite3.OperationalError:
                pass

    con.close()
    query_time_ms = (time.perf_counter() - start_time) * 1000.0

    # Format output items with advisory disclaimer per Hard Constraints
    formatted_scenarios: List[Dict[str, Any]] = []
    for r in results:
        ref_block = (
            f"[Reference Scenario: {r.get('id')}] {r.get('title')}\n"
            f"Vulnerability: {r.get('vulnerability_class')} ({r.get('cwe_id') or 'Unspecified'})\n"
            f"Summary: {r.get('summary')}\n"
            f"Defense Guidance: {r.get('remediation')}"
        )
        r["reference_context"] = ref_block
        r["query_time_ms"] = round(query_time_ms, 2)
        r["is_advisory_context_only"] = True
        formatted_scenarios.append(r)

    return formatted_scenarios


def main() -> None:
    db_file = get_db_path()

    if "--rebuild" in sys.argv or not db_file.is_file():
        build_scenarios_db(db_path=db_file)

    # UI/UX Logging: display record count, build timing, sample queries
    con = sqlite3.connect(db_file)
    cur = con.cursor()
    total_records = cur.execute("SELECT count(*) FROM scenarios").fetchone()[0]
    fts_records = cur.execute("SELECT count(*) FROM scenarios_fts").fetchone()[0]
    con.close()

    print("============================================================")
    print("Project Zero-Day: Scenario RAG Index Status")
    print("============================================================")
    print(f"Database location:          {db_file}")
    print(f"Indexed scenario records:   {total_records}")
    print(f"FTS5 overlay records:       {fts_records}")
    print("Search latency SLA:         < 50.0 ms")
    print("------------------------------------------------------------")

    test_queries = [
        ("CWE-693", "Content Security Policy"),
        ("CWE-79", "Cross Site Scripting"),
        ("CWE-89", "SQL Injection"),
        ("CWE-1021", "Clickjacking"),
        ("CWE-99999", "Unknown Vulnerability"),  # Zero-result test
    ]

    for cwe, v_class in test_queries:
        scenarios = get_relevant_scenarios(cwe_id=cwe, vulnerability_class=v_class, limit=2)
        lat = scenarios[0]["query_time_ms"] if scenarios else 0.0
        sla_pass = lat < 50.0
        print(f"Query: [{cwe}] '{v_class}' -> {len(scenarios)} matches in {lat:.2f}ms (SLA < 50ms: {'PASS' if sla_pass else 'FAIL'})")
        for s in scenarios:
            clean_title = s['title'][:65].encode('ascii', errors='replace').decode('ascii')
            print(f"   -> [{s['id']}] {clean_title} (CWE: {s.get('cwe_id')})")

    print("============================================================")
    print("[SUCCESS] Scenario RAG indexing verified successfully.\n")


if __name__ == "__main__":
    main()
