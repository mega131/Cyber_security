"""
Resets and restores the blockchain to clean Genesis state.
"""
import sqlite3
from app import create_app
from app.models.evidence import init_db

app = create_app()

conn = sqlite3.connect("data/forensic.db")
conn.execute("DROP TABLE IF EXISTS blockchain")
conn.execute("DROP TABLE IF EXISTS evidence")
conn.execute("DROP TABLE IF EXISTS verification_logs")
conn.commit()
conn.close()

# Reinitialize clean tables & Genesis block
init_db()
print("[✓] SUCCESS: Database and Blockchain have been restored to clean Genesis state (Block #0).")
