import hashlib
import time
import json
import sqlite3
from datetime import datetime, timezone
from app.config import Config

DIFFICULTY = 2  # Mining difficulty (hash must start with '0' * DIFFICULTY)

def calculate_block_hash(index_num, timestamp, evidence_id, case_number, file_hash, previous_hash, nonce):
    """
    Computes cryptographic SHA-256 hash of block contents.
    """
    block_string = f"{index_num}|{timestamp}|{evidence_id}|{case_number}|{file_hash}|{previous_hash}|{nonce}"
    return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

class ForensicBlockchain:
    def __init__(self, db_conn_func):
        self.get_db = db_conn_func

    def init_chain(self):
        """
        Creates the Genesis Block if the blockchain is empty.
        """
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM blockchain")
        count = cursor.fetchone()['count']
        
        if count == 0:
            # Mine Genesis Block (Block #0)
            genesis_timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            genesis_evidence = "GENESIS-ROOT"
            genesis_case = "CASE-ROOT-SYSTEM"
            genesis_file_hash = "0" * 64
            genesis_prev_hash = "0" * 64
            nonce = 0
            
            target_prefix = "0" * DIFFICULTY
            while True:
                h = calculate_block_hash(0, genesis_timestamp, genesis_evidence, genesis_case, genesis_file_hash, genesis_prev_hash, nonce)
                if h.startswith(target_prefix):
                    break
                nonce += 1
                
            cursor.execute('''
                INSERT INTO blockchain (index_num, timestamp, evidence_id, case_number, file_hash, previous_hash, nonce, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (0, genesis_timestamp, genesis_evidence, genesis_case, genesis_file_hash, genesis_prev_hash, nonce, h))
            conn.commit()
            
        conn.close()

    def get_latest_block(self):
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blockchain ORDER BY index_num DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def mine_evidence_block(self, evidence_id, case_number, file_hash):
        """
        Mines a new block linking to the previous block's hash with Proof of Work.
        """
        self.init_chain()
        latest_block = self.get_latest_block()
        
        index_num = latest_block['index_num'] + 1
        previous_hash = latest_block['block_hash']
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        nonce = 0
        target_prefix = "0" * DIFFICULTY
        
        # Proof-of-Work Mining loop
        start_time = time.time()
        while True:
            block_hash = calculate_block_hash(index_num, timestamp, evidence_id, case_number, file_hash, previous_hash, nonce)
            if block_hash.startswith(target_prefix):
                break
            nonce += 1
        mining_duration = round(time.time() - start_time, 4)
        
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO blockchain (index_num, timestamp, evidence_id, case_number, file_hash, previous_hash, nonce, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (index_num, timestamp, evidence_id, case_number, file_hash, previous_hash, nonce, block_hash))
        conn.commit()
        conn.close()
        
        return {
            'index_num': index_num,
            'timestamp': timestamp,
            'evidence_id': evidence_id,
            'case_number': case_number,
            'file_hash': file_hash,
            'previous_hash': previous_hash,
            'nonce': nonce,
            'block_hash': block_hash,
            'mining_duration_sec': mining_duration
        }

    def get_all_blocks(self):
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT b.*, e.original_filename, e.detected_type_label, e.examiner_name
            FROM blockchain b
            LEFT JOIN evidence e ON b.evidence_id = e.evidence_id
            ORDER BY b.index_num ASC
        ''')
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_block_by_evidence_id(self, evidence_id):
        conn = self.get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blockchain WHERE evidence_id = ?", (evidence_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def verify_chain(self):
        """
        Cryptographically validates the entire blockchain from Genesis Block to tip:
        1. Checks block hash integrity (re-calculates hash from contents).
        2. Validates Proof-of-Work difficulty.
        3. Verifies continuous chain linkage (block[i].previous_hash == block[i-1].block_hash).
        """
        blocks = self.get_all_blocks()
        if not blocks:
            return {'is_valid': True, 'total_blocks': 0, 'details': 'Blockchain ledger is empty.'}

        target_prefix = "0" * DIFFICULTY

        for i, block in enumerate(blocks):
            # Recalculate hash
            recomputed = calculate_block_hash(
                block['index_num'],
                block['timestamp'],
                block['evidence_id'],
                block['case_number'],
                block['file_hash'],
                block['previous_hash'],
                block['nonce']
            )

            # Check 1: Does stored hash match recalculated hash?
            if recomputed != block['block_hash']:
                return {
                    'is_valid': False,
                    'total_blocks': len(blocks),
                    'broken_index': block['index_num'],
                    'details': f"CRITICAL INTEGRITY BREACH at Block #{block['index_num']}: Computed hash ({recomputed}) does not match recorded block hash ({block['block_hash']}). Data has been tampered with!"
                }

            # Check 2: Does hash satisfy difficulty?
            if not block['block_hash'].startswith(target_prefix):
                return {
                    'is_valid': False,
                    'total_blocks': len(blocks),
                    'broken_index': block['index_num'],
                    'details': f"PoW Difficulty violated at Block #{block['index_num']}: Hash does not meet required difficulty prefix '{target_prefix}'."
                }

            # Check 3: Does previous_hash correctly link to predecessor?
            if i > 0:
                prev_block = blocks[i - 1]
                if block['previous_hash'] != prev_block['block_hash']:
                    return {
                        'is_valid': False,
                        'total_blocks': len(blocks),
                        'broken_index': block['index_num'],
                        'details': f"CHAIN LINK BROKEN at Block #{block['index_num']}: Previous hash link ({block['previous_hash']}) does not equal Block #{prev_block['index_num']} hash ({prev_block['block_hash']})."
                    }

        return {
            'is_valid': True,
            'total_blocks': len(blocks),
            'broken_index': None,
            'details': f"Blockchain verified cryptographically. All {len(blocks)} blocks (Genesis to Tip) have unbroken cryptographic links and valid Proof-of-Work."
        }
