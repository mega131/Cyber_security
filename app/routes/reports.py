from flask import Blueprint, send_file, flash, redirect, url_for
from app.models.evidence import get_evidence_by_id
from app.services.report_generator import build_pdf_report

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/reports/<evidence_id>/download')
def download_report(evidence_id):
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        flash(f'Evidence record "{evidence_id}" not found.', 'error')
        return redirect(url_for('evidence.history'))
        
    pdf_stream = build_pdf_report(evidence)
    
    download_filename = f"Forensic_Report_{evidence_id}.pdf"
    return send_file(
        pdf_stream,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=download_filename
    )
