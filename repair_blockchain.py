"""
Repairs a tampered block by restoring its genuine file_hash from the evidence vault record.
This demonstrates how an investigator restores the verified state to make the blockchain valid again.
"""
import sqlite3
from pathlib import Path

db_path = Path("data/forensic.db")
if not db_path.exists():
    print("[!] Database not found.")
    exit(1)

conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

# Retrieve the genuine SHA-256 from the evidence record corresponding to Block #1
cursor.execute('''
    SELECT e.sha256_hash, b.index_num, b.evidence_id 
    FROM blockchain b 
    JOIN evidence e ON b.evidence_id = e.evidence_id 
    WHERE b.index_num = 1
''')
row = cursor.fetchone()

if row:
    genuine_hash, block_idx, evidence_id = row
    cursor.execute("UPDATE blockchain SET file_hash = ? WHERE index_num = ?", (genuine_hash, block_idx))
    conn.commit()
    print(f"[✓] SUCCESS: Block #{block_idx} ({evidence_id}) has been repaired!")
    print(f"    Restored authentic file hash: {genuine_hash[:16]}...{genuine_hash[-8:]}")
    print("[✓] Now go to http://127.0.0.1:5000/blockchain and click 'Verify Blockchain Integrity'.")
    print("    It will now be VALID (GREEN) again!")
else:
    print("[!] No evidence link found for Block #1.")

conn.close()
