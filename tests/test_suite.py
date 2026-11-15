import os
import io
import unittest
from pathlib import Path
from PIL import Image
from reportlab.pdfgen import canvas

from app import create_app
from app.config import Config
from app.models.evidence import (
    init_db,
    save_evidence_record,
    get_all_evidence,
    get_evidence_by_id,
    get_dashboard_metrics,
    get_db_connection
)
from app.services.hasher import calculate_hashes, calculate_stream_sha256
from app.services.validator import inspect_file_signature
from app.services.metadata_extractor import extract_metadata
from app.services.integrity_service import verify_file_integrity
from app.services.report_generator import build_pdf_report

class TestForensicAnalyzer(unittest.TestCase):
    def setUp(self):
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

    def test_database_initialization(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence'")
        table = cursor.fetchone()
        self.assertIsNotNone(table, "Evidence table should be initialized.")
        conn.close()

    def test_hashing_consistency(self):
        test_content = b"Digital Forensic Evidence Analyzer Integrity Test"
        test_file = self.test_dir / "hash_test.txt"
        test_file.write_bytes(test_content)
        
        hashes = calculate_hashes(str(test_file))
        self.assertEqual(len(hashes['md5']), 32)
        self.assertEqual(len(hashes['sha256']), 64)
        
        # Test stream hash calculation
        stream_hash = calculate_stream_sha256(io.BytesIO(test_content))
        self.assertEqual(hashes['sha256'], stream_hash)

    def test_magic_byte_and_spoof_detection(self):
        # 1. Real PNG image
        png_file = self.test_dir / "sample.png"
        img = Image.new('RGB', (100, 100), color='red')
        img.save(png_file, format='PNG')
        
        valid_res = inspect_file_signature(str(png_file), "sample.png")
        self.assertEqual(valid_res['status'], 'MATCH')
        self.assertEqual(valid_res['detected_mime'], 'image/png')
        
        # 2. Spoofed file: text disguised as .jpg
        spoofed_file = self.test_dir / "spoofed.jpg"
        spoofed_file.write_bytes(b"This is a malware disguised as an image")
        
        spoof_res = inspect_file_signature(str(spoofed_file), "spoofed.jpg")
        self.assertEqual(spoof_res['status'], 'MISMATCH')
        self.assertIn('ANOMALY DETECTED', spoof_res['details'])

    def test_pdf_report_generation(self):
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
            'metadata': {
                'attributes': {'Page Count': 2, 'Is Encrypted': 'No'},
                'doc_info': {'Title': 'Confidential Report'},
                'timestamps': {
                    'os_creation_time': '2026-11-14 10:00:00 UTC',
                    'os_modification_time': '2026-11-14 10:00:00 UTC',
                    'os_access_time': '2026-11-14 10:00:00 UTC'
                }
            }
        }
        
        pdf_stream = build_pdf_report(sample_evidence)
        pdf_bytes = pdf_stream.read()
        self.assertTrue(len(pdf_bytes) > 1000, "Generated PDF should have non-trivial size.")
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'), "Generated file should have valid PDF header.")

    def test_routes_accessible(self):
        r_dashboard = self.client.get('/')
        self.assertEqual(r_dashboard.status_code, 200)
        self.assertIn(b'Forensic Operations Dashboard', r_dashboard.data)

        r_upload = self.client.get('/upload')
        self.assertEqual(r_upload.status_code, 200)

        r_integrity = self.client.get('/integrity')
        self.assertEqual(r_integrity.status_code, 200)

        r_history = self.client.get('/history')
        self.assertEqual(r_history.status_code, 200)

    def test_full_evidence_intake_and_integrity_cycle(self):
        # 1. Ingest evidence
        original_data = b"Case #42 Secret Forensic Evidence Log\nTimestamp: 2026-11-14\nUser: admin\n"
        upload_resp = self.client.post('/upload', data={
            'evidence_file': (io.BytesIO(original_data), 'incident_log.txt'),
            'case_number': 'CASE-2026-TEST',
            'examiner_name': 'Detective Python',
            'notes': 'Seized from suspected host memory dump'
        }, follow_redirects=True)
        
        self.assertEqual(upload_resp.status_code, 200)
        self.assertIn(b'incident_log.txt', upload_resp.data)
        self.assertIn(b'SHA-256 Digest', upload_resp.data)
        
        # Extract evidence ID from URL or page
        all_records = get_all_evidence()
        test_record = next((r for r in all_records if r['original_filename'] == 'incident_log.txt'), None)
        self.assertIsNotNone(test_record)
        evidence_id = test_record['evidence_id']
        
        # 2. Verify Integrity with IDENTICAL file
        verify_match_resp = self.client.post('/integrity', data={
            'evidence_id': evidence_id,
            'test_file': (io.BytesIO(original_data), 'incident_log_copy.txt')
        }, follow_redirects=True)
        self.assertEqual(verify_match_resp.status_code, 200)
        self.assertIn(b'INTEGRITY VERIFIED: BITSTREAMS IDENTICAL', verify_match_resp.data)
        
        # 3. Verify Integrity with TAMPERED file
        tampered_data = b"Case #42 Secret Forensic Evidence Log\nTimestamp: 2026-11-14\nUser: intruder\n"
        verify_tamper_resp = self.client.post('/integrity', data={
            'evidence_id': evidence_id,
            'test_file': (io.BytesIO(tampered_data), 'incident_log_tampered.txt')
        }, follow_redirects=True)
        self.assertEqual(verify_tamper_resp.status_code, 200)
        self.assertIn(b'INTEGRITY BREACH / HASH MISMATCH DETECTED', verify_tamper_resp.data)
        
        # 4. Download PDF report
        report_resp = self.client.get(f'/reports/{evidence_id}/download')
        self.assertEqual(report_resp.status_code, 200)
        self.assertEqual(report_resp.content_type, 'application/pdf')
        self.assertTrue(report_resp.data.startswith(b'%PDF-'))
        self.assertIn('attachment;', report_resp.headers.get('Content-Disposition', ''))

if __name__ == '__main__':
    unittest.main()
