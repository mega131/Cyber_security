from flask import Blueprint, render_template, jsonify, request
from app.models.evidence import get_blockchain

blockchain_bp = Blueprint('blockchain', __name__)

@blockchain_bp.route('/blockchain')
def index():
    chain = get_blockchain()
    blocks = chain.get_all_blocks()
    audit_result = chain.verify_chain()
    return render_template(
        'blockchain.html',
        blocks=blocks,
        audit_result=audit_result,
        total_blocks=len(blocks)
    )

@blockchain_bp.route('/api/blockchain/verify', methods=['POST'])
def api_verify():
    chain = get_blockchain()
    audit_result = chain.verify_chain()
    return jsonify(audit_result)
