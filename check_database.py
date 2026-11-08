import sqlite3

c = sqlite3.connect("scenarios.db")
print("Base:", c.execute("SELECT COUNT(*) FROM scenarios").fetchone())
print("FTS:", c.execute("SELECT COUNT(*) FROM scenarios_fts").fetchone())
print("Sample:", c.execute(
    "SELECT title FROM scenarios_fts LIMIT 3"
).fetchall())
c.close()