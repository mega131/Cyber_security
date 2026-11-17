import os
import io
import unittest
from pathlib import Path
from PIL import Image

from app import create_app
from app.config import Config
from app.models.evidence import (
    init_db,
    save_evidence_record,
    get_all_evidence,
    get_evidence_by_id,
    get_dashboard_metrics,
    get_db_connection,
    get_blockchain
)
from app.services.hasher import calculate_hashes, calculate_stream_sha256
from app.services.validator import inspect_file_signature
from app.services.metadata_extractor import extract_metadata
from app.services.integrity_service import verify_file_integrity
from app.services.report_generator import build_pdf_report
from app.services.blockchain import ForensicBlockchain, calculate_block_hash
from app.services.ai_analyzer import analyze_evidence_with_ai

class TestForensicAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_db_path = Config.DATA_FOLDER / 'test_forensic.db'
        Config.DATABASE_PATH = self.test_db_path
        if self.test_db_path.exists():
            try:
                self.test_db_path.unlink()
            except Exception:
                pass
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.test_dir = Path(__file__).resolve().parent / 'test_samples'
        self.test_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.test_dir.exists():
            for f in self.test_dir.iterdir():
                try:
                    f.unlink()
                except Exception:
                    pass
        Config.DATABASE_PATH = Config.DATA_FOLDER / 'forensic.db'
        if hasattr(self, 'test_db_path') and self.test_db_path.exists():
            try:
                self.test_db_path.unlink()
            except Exception:
                pass

    def test_database_initialization(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence'")
        table = cursor.fetchone()
        self.assertIsNotNone(table, "Evidence table should be initialized.")
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='blockchain'")
        b_table = cursor.fetchone()
        self.assertIsNotNone(b_table, "Blockchain table should be initialized.")
        conn.close()

    def test_blockchain_mining_and_tamper_detection(self):
        chain = get_blockchain()
        # Verify genesis block exists
        blocks = chain.get_all_blocks()
        self.assertTrue(len(blocks) >= 1)
        self.assertEqual(blocks[0]['index_num'], 0)
        self.assertEqual(blocks[0]['evidence_id'], 'GENESIS-ROOT')
        
        # Mine an evidence block
        block = chain.mine_evidence_block('EVD-TEST-MINE', 'CASE-TEST', 'b' * 64)
        self.assertIsNotNone(block)
        self.assertTrue(block['block_hash'].startswith('00'))
        
        # Verify chain validity
        audit = chain.verify_chain()
        self.assertTrue(audit['is_valid'])
        
        # Now simulate rogue tampering in SQLite
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE blockchain SET file_hash = 'tampered_data' WHERE evidence_id = 'EVD-TEST-MINE'")
        conn.commit()
        conn.close()
        
        # Chain verification MUST fail and detect tampering
        tampered_audit = chain.verify_chain()
        self.assertFalse(tampered_audit['is_valid'])
        self.assertIn("CRITICAL INTEGRITY BREACH", tampered_audit['details'])

    def test_ai_forensic_analyzer(self):
        # 1. Clean file analysis
        clean_ai = analyze_evidence_with_ai(
            original_filename="sample.png",
            declared_mime="image/png",
            detected_mime="image/png",
            signature_status="MATCH",
            signature_details="Header matches PNG",
            file_size_bytes=50000,
            metadata={"attributes": {"Dimensions": "800 x 600"}}
        )
        self.assertEqual(clean_ai['threat_level'], "LOW")
        self.assertTrue(clean_ai['risk_score'] < 30)

        # 2. Critical threat: Spoofed extension with plaintext payload
        spoofed_ai = analyze_evidence_with_ai(
            original_filename="malicious.jpg",
            declared_mime="image/jpeg",
            detected_mime="text/plain",
            signature_status="MISMATCH",
            signature_details="ANOMALY DETECTED: Plain text in jpg",
            file_size_bytes=120,
            metadata={"attributes": {"Preview": "powershell -enc aW52b2tlLW1pbWlrYXR6"}}
        )
        self.assertEqual(spoofed_ai['threat_level'], "CRITICAL")
        self.assertTrue(spoofed_ai['risk_score'] >= 75)
        self.assertTrue(any("EXTENSION SPOOFING" in f for f in spoofed_ai['risk_factors']))

    def test_hashing_consistency(self):
        test_content = b"Digital Forensic Evidence Analyzer Integrity Test"
        test_file = self.test_dir / "hash_test.txt"
        test_file.write_bytes(test_content)
        
        hashes = calculate_hashes(str(test_file))
        self.assertEqual(len(hashes['md5']), 32)
        self.assertEqual(len(hashes['sha256']), 64)
        
        stream_hash = calculate_stream_sha256(io.BytesIO(test_content))
        self.assertEqual(hashes['sha256'], stream_hash)

    def test_magic_byte_and_spoof_detection(self):
        png_file = self.test_dir / "sample.png"
        img = Image.new('RGB', (100, 100), color='red')
        img.save(png_file, format='PNG')
        
        valid_res = inspect_file_signature(str(png_file), "sample.png")
        self.assertEqual(valid_res['status'], 'MATCH')
        self.assertEqual(valid_res['detected_mime'], 'image/png')
        
        spoofed_file = self.test_dir / "spoofed.jpg"
        spoofed_file.write_bytes(b"This is a malware disguised as an image")
        
        spoof_res = inspect_file_signature(str(spoofed_file), "spoofed.jpg")
        self.assertEqual(spoof_res['status'], 'MISMATCH')
        self.assertIn('ANOMALY DETECTED', spoof_res['details'])

    def test_pdf_report_generation_with_ai_and_blockchain(self):
        sample_evidence = {
            'evidence_id': 'EVD-TEST-001',
            'case_number': 'CASE-TEST-99',
            'examiner_name': 'Lead Examiner',
            'original_filename': 'document.pdf',
            'stored_filename': 'EVD-TEST-001_document.pdf',
            'file_extension': 'pdf',
            'file_size_bytes': 10240,
            'file_size_formatted': '10.00 KB',
            'declared_mime': 'application/pdf',
            'detected_mime': 'application/pdf',
            'detected_type_label': 'PDF Document',
            'signature_status': 'MATCH',
            'signature_details': 'Header signature verified (%PDF-).',
            'md5_hash': '0123456789abcdef0123456789abcdef',
            'sha256_hash': 'a' * 64,
            'created_at': '2026-11-14 12:00:00',
            'notes': 'Test ingestion note',
            'block_index': 1,
            'block_hash': '00' + 'f' * 62,
            'block_info': {
                'index_num': 1,
                'block_hash': '00' + 'f' * 62,
                'previous_hash': '00' + 'e' * 62,
                'nonce': 1234,
                'timestamp': '2026-11-14 12:00:01 UTC'
            },
            'ai_analysis': {
                'threat_level': 'LOW',
                'threat_badge': 'BENIGN / LOW RISK',
                'risk_score': 10,
                'executive_summary': 'File is structurally consistent.',
                'recommendations': ['Record baseline.']
            }
        }
        
        pdf_stream = build_pdf_report(sample_evidence)
        pdf_bytes = pdf_stream.read()
        self.assertTrue(len(pdf_bytes) > 1000)
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'))

    def test_routes_accessible(self):
        r_dashboard = self.client.get('/')
        self.assertEqual(r_dashboard.status_code, 200)
        self.assertIn(b'Forensic Operations Dashboard', r_dashboard.data)

        r_blockchain = self.client.get('/blockchain')
        self.assertEqual(r_blockchain.status_code, 200)
        self.assertIn(b'Cryptographic Blockchain Ledger', r_blockchain.data)

        r_upload = self.client.get('/upload')
        self.assertEqual(r_upload.status_code, 200)

        r_integrity = self.client.get('/integrity')
        self.assertEqual(r_integrity.status_code, 200)

        r_history = self.client.get('/history')
        self.assertEqual(r_history.status_code, 200)

    def test_full_evidence_intake_and_integrity_cycle(self):
        original_data = b"Case #42 Secret Forensic Evidence Log\nTimestamp: 2026-11-14\nUser: admin\n"
        upload_resp = self.client.post('/upload', data={
            'evidence_file': (io.BytesIO(original_data), 'incident_log.txt'),
            'case_number': 'CASE-2026-TEST',
            'examiner_name': 'Detective Python',
            'notes': 'Seized from suspected host memory dump'
        }, follow_redirects=True)
        
        self.assertEqual(upload_resp.status_code, 200)
        self.assertIn(b'incident_log.txt', upload_resp.data)
        
        # Verify AI and Blockchain are rendered on details page
        self.assertIn(b'AI Forensic Threat Assessment', upload_resp.data)
        self.assertIn(b'Blockchain Proof of Custody', upload_resp.data)
        
        all_records = get_all_evidence()
        test_record = next((r for r in all_records if r['original_filename'] == 'incident_log.txt'), None)
        self.assertIsNotNone(test_record)
        evidence_id = test_record['evidence_id']
        
        # Test download PDF report
        report_resp = self.client.get(f'/reports/{evidence_id}/download')
        self.assertEqual(report_resp.status_code, 200)
        self.assertEqual(report_resp.content_type, 'application/pdf')
        self.assertTrue(report_resp.data.startswith(b'%PDF-'))
        self.assertIn('attachment;', report_resp.headers.get('Content-Disposition', ''))

if __name__ == '__main__':
    unittest.main()
