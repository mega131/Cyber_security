"""
Simulates an unauthorized insider / DBA tampering with the blockchain record in SQLite.
"""
import sqlite3
from pathlib import Path

db_path = Path("data/forensic.db")
if not db_path.exists():
    print("[!] Database data/forensic.db does not exist yet. Please run the app and upload evidence first.")
    exit(1)

conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Check if Block #1 exists
cursor.execute("SELECT COUNT(*) as cnt FROM blockchain WHERE index_num = 1")
count = cursor.fetchone()[0]

if count == 0:
    print("[!] Block #1 does not exist yet.")
    print("    Please upload at least 1 evidence file on http://127.0.0.1:5000/upload first!")
else:
    # Tamper with the recorded hash of Block #1
    cursor.execute("UPDATE blockchain SET file_hash = 'ILLEGALLY_ALTERED_HASH_999999' WHERE index_num = 1")
    conn.commit()
    print("[+] SUCCESS: Block #1 has been secretly tampered with in data/forensic.db!")
    print("[+] Now go to http://127.0.0.1:5000/blockchain and click 'Verify Blockchain Integrity' to see the alert!")

conn.close()
