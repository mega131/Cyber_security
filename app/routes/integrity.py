from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from app.models.evidence import get_all_evidence, get_verification_logs, get_evidence_by_id
from app.services.integrity_service import verify_file_integrity

integrity_bp = Blueprint('integrity', __name__)

@integrity_bp.route('/integrity', methods=['GET', 'POST'])
def index():
    evidence_list = get_all_evidence(limit=100)
    preselected_id = request.args.get('target', '')
    verification_result = None
    
    if request.method == 'POST':
        evidence_id = request.form.get('evidence_id', '').strip()
        test_file = request.files.get('test_file')
        
        if not evidence_id:
            flash('Please select or specify a target Evidence ID for baseline comparison.', 'error')
        elif not test_file or test_file.filename == '':
            flash('Please upload a test evidence file to verify.', 'error')
        else:
            verification_result = verify_file_integrity(
                evidence_id=evidence_id,
                test_file_stream=test_file.stream,
                test_filename=test_file.filename
            )
            preselected_id = evidence_id
            
    recent_logs = get_verification_logs(limit=15)
    return render_template(
        'integrity.html',
        evidence_list=evidence_list,
        preselected_id=preselected_id,
        result=verification_result,
        recent_logs=recent_logs
    )

@integrity_bp.route('/api/verify', methods=['POST'])
def api_verify():
    evidence_id = request.form.get('evidence_id', '').strip()
    test_file = request.files.get('test_file')
    
    if not evidence_id or not test_file:
        return jsonify({'success': False, 'error': 'Missing evidence_id or test_file'}), 400
        
    result = verify_file_integrity(
        evidence_id=evidence_id,
        test_file_stream=test_file.stream,
        test_filename=test_file.filename
    )
    return jsonify(result)
