from flask import Blueprint, render_template, jsonify
from app.models.evidence import get_dashboard_metrics

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    metrics = get_dashboard_metrics()
    return render_template('dashboard.html', metrics=metrics)

@dashboard_bp.route('/api/stats')
def stats_api():
    metrics = get_dashboard_metrics()
    return jsonify({
        'total_count': metrics['total_count'],
        'total_bytes': metrics['total_bytes'],
        'total_verifications': metrics['total_verifications'],
        'matched_count': metrics['matched_count'],
        'mismatch_count': metrics['mismatch_count'],
        'type_distribution': metrics['type_distribution'],
        'signature_stats': metrics['signature_stats']
    })
