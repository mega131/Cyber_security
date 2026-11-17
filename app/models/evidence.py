import sqlite3
import json
from datetime import datetime
from pathlib import Path
from app.config import Config

def get_db_connection():
    Config.DATA_FOLDER.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(Config.DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def get_blockchain():
    from app.services.blockchain import ForensicBlockchain
    return ForensicBlockchain(get_db_connection)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Evidence Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT UNIQUE NOT NULL,
            case_number TEXT DEFAULT 'CASE-DEFAULT',
            examiner_name TEXT DEFAULT 'Forensic Analyst',
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_extension TEXT NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            file_size_formatted TEXT NOT NULL,
            declared_mime TEXT,
            detected_mime TEXT,
            detected_type_label TEXT,
            signature_status TEXT,
            signature_details TEXT,
            md5_hash TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            metadata_json TEXT,
            notes TEXT,
            ai_threat_level TEXT DEFAULT 'LOW',
            ai_risk_score INTEGER DEFAULT 10,
            ai_analysis_json TEXT,
            block_index INTEGER DEFAULT 0,
            block_hash TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if migration needed for existing tables
    cursor.execute("PRAGMA table_info(evidence)")
    existing_cols = [row['name'] for row in cursor.fetchall()]
    new_cols = [
        ('ai_threat_level', "TEXT DEFAULT 'LOW'"),
        ('ai_risk_score', "INTEGER DEFAULT 10"),
        ('ai_analysis_json', "TEXT"),
        ('block_index', "INTEGER DEFAULT 0"),
        ('block_hash', "TEXT DEFAULT ''")
    ]
    for col_name, col_def in new_cols:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE evidence ADD COLUMN {col_name} {col_def}")
            
    # 2. Verification Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS verification_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL,
            test_filename TEXT NOT NULL,
            test_sha256 TEXT NOT NULL,
            baseline_sha256 TEXT NOT NULL,
            match_status INTEGER NOT NULL,
            verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id)
        )
    ''')
    
    # 3. Cryptographic Blockchain Ledger Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blockchain (
            index_num INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            case_number TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            nonce INTEGER NOT NULL,
            block_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

    # Initialize Genesis block if blockchain is empty
    chain = get_blockchain()
    chain.init_chain()

def save_evidence_record(data):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO evidence (
            evidence_id, case_number, examiner_name, original_filename,
            stored_filename, file_extension, file_size_bytes, file_size_formatted,
            declared_mime, detected_mime, detected_type_label, signature_status,
            signature_details, md5_hash, sha256_hash, metadata_json, notes,
            ai_threat_level, ai_risk_score, ai_analysis_json, block_index, block_hash
        ) VALUES (
            :evidence_id, :case_number, :examiner_name, :original_filename,
            :stored_filename, :file_extension, :file_size_bytes, :file_size_formatted,
            :declared_mime, :detected_mime, :detected_type_label, :signature_status,
            :signature_details, :md5_hash, :sha256_hash, :metadata_json, :notes,
            :ai_threat_level, :ai_risk_score, :ai_analysis_json, :block_index, :block_hash
        )
    ''', data)
    conn.commit()
    conn.close()

def get_all_evidence(search=None, file_type=None, limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = 'SELECT * FROM evidence WHERE 1=1'
    params = []
    
    if search:
        query += ' AND (original_filename LIKE ? OR evidence_id LIKE ? OR case_number LIKE ? OR sha256_hash LIKE ? OR ai_threat_level LIKE ?)'
        wildcard = f'%{search}%'
        params.extend([wildcard, wildcard, wildcard, wildcard, wildcard])
    
    if file_type and file_type != 'all':
        query += ' AND detected_type_label LIKE ?'
        params.append(f'%{file_type}%')
        
    query += ' ORDER BY created_at DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_evidence_by_id(evidence_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM evidence WHERE evidence_id = ?', (evidence_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        d = dict(row)
        # Parse metadata
        if d.get('metadata_json'):
            try:
                d['metadata'] = json.loads(d['metadata_json'])
            except Exception:
                d['metadata'] = {}
        else:
            d['metadata'] = {}
            
        # Parse AI analysis
        if d.get('ai_analysis_json'):
            try:
                d['ai_analysis'] = json.loads(d['ai_analysis_json'])
            except Exception:
                d['ai_analysis'] = None
        else:
            d['ai_analysis'] = None
            
        # Retrieve Block Info
        chain = get_blockchain()
        d['block_info'] = chain.get_block_by_evidence_id(evidence_id)
        
        return d
    return None

def log_verification(evidence_id, test_filename, test_sha256, baseline_sha256, match_status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO verification_logs (
            evidence_id, test_filename, test_sha256, baseline_sha256, match_status
        ) VALUES (?, ?, ?, ?, ?)
    ''', (evidence_id, test_filename, test_sha256, baseline_sha256, 1 if match_status else 0))
    conn.commit()
    conn.close()

def get_verification_logs(evidence_id=None, limit=20):
    conn = get_db_connection()
    cursor = conn.cursor()
    if evidence_id:
        cursor.execute('''
            SELECT * FROM verification_logs 
            WHERE evidence_id = ? 
            ORDER BY verified_at DESC LIMIT ?
        ''', (evidence_id, limit))
    else:
        cursor.execute('''
            SELECT vl.*, e.original_filename as baseline_filename
            FROM verification_logs vl
            LEFT JOIN evidence e ON vl.evidence_id = e.evidence_id
            ORDER BY vl.verified_at DESC LIMIT ?
        ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_dashboard_metrics():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total evidence count & size
    cursor.execute('SELECT COUNT(*) as total_count, COALESCE(SUM(file_size_bytes), 0) as total_bytes FROM evidence')
    totals = cursor.fetchone()
    total_count = totals['total_count']
    total_bytes = totals['total_bytes']
    
    # Total verifications
    cursor.execute('SELECT COUNT(*) as total_verifications, COALESCE(SUM(match_status), 0) as matched_count FROM verification_logs')
    v_stats = cursor.fetchone()
    total_verifications = v_stats['total_verifications']
    matched_count = v_stats['matched_count']
    mismatch_count = total_verifications - matched_count
    
    # Blockchain blocks count
    cursor.execute('SELECT COUNT(*) as total_blocks FROM blockchain')
    total_blocks = cursor.fetchone()['total_blocks']
    
    # AI Threat Level Breakdown
    cursor.execute('SELECT ai_threat_level, COUNT(*) as count FROM evidence GROUP BY ai_threat_level')
    threat_rows = cursor.fetchall()
    ai_threat_stats = {r['ai_threat_level']: r['count'] for r in threat_rows}
    for lvl in ['LOW', 'ELEVATED', 'SUSPICIOUS', 'CRITICAL']:
        ai_threat_stats.setdefault(lvl, 0)
    
    # Type distribution
    cursor.execute('''
        SELECT 
            CASE 
                WHEN detected_type_label LIKE '%Image%' THEN 'Images'
                WHEN detected_type_label LIKE '%PDF%' THEN 'PDF Documents'
                WHEN detected_type_label LIKE '%Text%' OR detected_type_label LIKE '%Plain%' THEN 'Plain Text / Logs'
                ELSE 'Other'
            END as category,
            COUNT(*) as count
        FROM evidence
        GROUP BY category
    ''')
    type_rows = cursor.fetchall()
    type_distribution = {row['category']: row['count'] for row in type_rows}
    for cat in ['Images', 'PDF Documents', 'Plain Text / Logs']:
        type_distribution.setdefault(cat, 0)
        
    # Signature integrity status breakdown
    cursor.execute('SELECT signature_status, COUNT(*) as count FROM evidence GROUP BY signature_status')
    sig_rows = cursor.fetchall()
    sig_stats = {row['signature_status']: row['count'] for row in sig_rows}
    
    # Recent 5 evidence files
    cursor.execute('SELECT * FROM evidence ORDER BY created_at DESC LIMIT 5')
    recent_evidence = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    
    return {
        'total_count': total_count,
        'total_bytes': total_bytes,
        'total_verifications': total_verifications,
        'matched_count': matched_count,
        'mismatch_count': mismatch_count,
        'total_blocks': total_blocks,
        'ai_threat_stats': ai_threat_stats,
        'type_distribution': type_distribution,
        'signature_stats': sig_stats,
        'recent_evidence': recent_evidence
    }
