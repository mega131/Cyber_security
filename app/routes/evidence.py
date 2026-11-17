import os
import uuid
import json
from datetime import datetime
from pathlib import Path
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from werkzeug.utils import secure_filename

from app.config import Config
from app.models.evidence import (
    save_evidence_record,
    get_all_evidence,
    get_evidence_by_id,
    get_blockchain
)
from app.services.hasher import calculate_hashes
from app.services.validator import inspect_file_signature
from app.services.metadata_extractor import extract_metadata
from app.services.ai_analyzer import analyze_evidence_with_ai

evidence_bp = Blueprint('evidence', __name__)

def format_size(bytes_val):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"

def is_allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in Config.ALLOWED_EXTENSIONS

@evidence_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'evidence_file' not in request.files:
            flash('No file part selected.', 'error')
            return redirect(request.url)
            
        file = request.files['evidence_file']
        if file.filename == '':
            flash('No file selected for forensic intake.', 'error')
            return redirect(request.url)
            
        original_name = file.filename
        if not is_allowed_file(original_name):
            flash(f'File type not allowed. Supported formats: {", ".join(sorted(Config.ALLOWED_EXTENSIONS))}', 'error')
            return redirect(request.url)
            
        case_number = request.form.get('case_number', '').strip() or 'CASE-DEFAULT'
        examiner_name = request.form.get('examiner_name', '').strip() or 'Forensic Analyst'
        notes = request.form.get('notes', '').strip()
        
        # Safe storage path with UUID
        Config.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        evidence_uuid = f"EVD-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        safe_name = secure_filename(original_name)
        stored_name = f"{evidence_uuid}_{safe_name}"
        save_path = Config.UPLOAD_FOLDER / stored_name
        
        # Save uploaded evidence
        file.save(str(save_path))
        
        # Read-only attributes / non-destructive intake
        try:
            os.chmod(str(save_path), 0o444)
        except Exception:
            pass
            
        # 1. Calculate File Size
        size_bytes = os.path.getsize(str(save_path))
        size_formatted = format_size(size_bytes)
        file_ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
        
        # 2. Cryptographic Hashing (MD5 + SHA-256)
        hashes = calculate_hashes(str(save_path))
        
        # 3. Magic Header Signature Inspection
        sig_info = inspect_file_signature(str(save_path), original_name)
        
        # 4. Deep Metadata Extraction
        metadata = extract_metadata(str(save_path), sig_info['detected_mime'])
        
        # 5. AI Forensic Threat Analysis
        ai_result = analyze_evidence_with_ai(
            original_filename=original_name,
            declared_mime=file.content_type or 'application/octet-stream',
            detected_mime=sig_info['detected_mime'],
            signature_status=sig_info['status'],
            signature_details=sig_info['details'],
            file_size_bytes=size_bytes,
            metadata=metadata
        )
        
        # 6. Mine Block in Blockchain Ledger
        chain = get_blockchain()
        mined_block = chain.mine_evidence_block(
            evidence_id=evidence_uuid,
            case_number=case_number,
            file_hash=hashes['sha256']
        )
        
        # 7. Persist into SQLite
        record_data = {
            'evidence_id': evidence_uuid,
            'case_number': case_number,
            'examiner_name': examiner_name,
            'original_filename': original_name,
            'stored_filename': stored_name,
            'file_extension': file_ext,
            'file_size_bytes': size_bytes,
            'file_size_formatted': size_formatted,
            'declared_mime': file.content_type or 'application/octet-stream',
            'detected_mime': sig_info['detected_mime'],
            'detected_type_label': sig_info['detected_label'],
            'signature_status': sig_info['status'],
            'signature_details': sig_info['details'],
            'md5_hash': hashes['md5'],
            'sha256_hash': hashes['sha256'],
            'metadata_json': json.dumps(metadata),
            'notes': notes,
            'ai_threat_level': ai_result['threat_level'],
            'ai_risk_score': ai_result['risk_score'],
            'ai_analysis_json': json.dumps(ai_result),
            'block_index': mined_block['index_num'],
            'block_hash': mined_block['block_hash']
        }
        
        save_evidence_record(record_data)
        flash(f'Evidence "{original_name}" ingested, analyzed by AI, and anchored to Blockchain Block #{mined_block["index_num"]}.', 'success')
        return redirect(url_for('evidence.detail', evidence_id=evidence_uuid))
        
    return render_template('upload.html', allowed_extensions=sorted(list(Config.ALLOWED_EXTENSIONS)))

@evidence_bp.route('/evidence/<evidence_id>')
def detail(evidence_id):
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        flash(f'Evidence record "{evidence_id}" not found.', 'error')
        return redirect(url_for('evidence.history'))
    return render_template('evidence_detail.html', evidence=evidence)

@evidence_bp.route('/history')
def history():
    search = request.args.get('q', '').strip()
    file_type = request.args.get('type', 'all').strip()
    records = get_all_evidence(search=search, file_type=file_type)
    return render_template('history.html', records=records, search=search, selected_type=file_type)
