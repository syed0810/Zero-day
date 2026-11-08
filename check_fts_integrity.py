#!/usr/bin/env python3
"""
FTS5 Structural and Content Integrity Check for scenarios.db.
"""
import shutil
import sqlite3
import tempfile
from pathlib import Path

source = Path("scenarios.db").resolve()

if not source.exists():
    # Also search parent directory or standard locations
    if (Path(__file__).resolve().parent / "scenarios.db").exists():
        source = (Path(__file__).resolve().parent / "scenarios.db").resolve()
    else:
        raise FileNotFoundError(f"Database not found: {source}")

with tempfile.TemporaryDirectory() as temp_dir:
    copy_path = Path(temp_dir) / "scenarios_test.db"
    shutil.copy2(source, copy_path)

    connection = sqlite3.connect(copy_path)

    try:
        print("Running FTS5 integrity check on temporary copy...")

        connection.execute("""
            INSERT INTO scenarios_fts(scenarios_fts, rank)
            VALUES ('integrity-check', 1)
        """)

        print("PASS: FTS5 structural and content integrity check succeeded.")

    except sqlite3.Error as error:
        print("FAIL: FTS5 integrity check reported an error:")
        print(error)

    finally:
        connection.close()
