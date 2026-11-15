import hashlib
from app.services.hasher import calculate_hashes, calculate_stream_sha256
from app.models.evidence import get_evidence_by_id, log_verification

def verify_file_integrity(evidence_id, test_file_stream, test_filename):
    """
    Verifies an incoming file stream against the recorded SHA-256 hash of an existing evidence record.
    Returns:
        dict: {
            'evidence_id': str,
            'match': bool,
            'baseline_sha256': str,
            'test_sha256': str,
            'baseline_filename': str,
            'test_filename': str,
            'status_label': 'INTEGRITY VERIFIED' | 'INTEGRITY COMPROMISED / MISMATCH',
            'explanation': str
        }
    """
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        return {
            'success': False,
            'error': f'Evidence record with ID "{evidence_id}" was not found.'
        }
        
    baseline_sha256 = evidence['sha256_hash'].lower().strip()
    test_sha256 = calculate_stream_sha256(test_file_stream).lower().strip()
    
    is_match = (baseline_sha256 == test_sha256)
    
    # Log verification attempt in database for audit trail
    log_verification(
        evidence_id=evidence_id,
        test_filename=test_filename,
        test_sha256=test_sha256,
        baseline_sha256=baseline_sha256,
        match_status=is_match
    )
    
    if is_match:
        explanation = (
            "The computed SHA-256 digest of the submitted file matches the recorded baseline hash. "
            "This cryptographically verifies that the bitstream is identical to the evidence state at the time of intake. "
            "(Note: This verifies preservation integrity, not pre-seizure authenticity)."
        )
        status_label = "INTEGRITY VERIFIED"
    else:
        explanation = (
            "ALERT: The computed SHA-256 digest differs from the recorded baseline hash. "
            "The submitted file has been altered, corrupted, or is not the same bitstream as the ingested evidence."
        )
        status_label = "INTEGRITY COMPROMISED / MISMATCH"
        
    return {
        'success': True,
        'evidence_id': evidence_id,
        'match': is_match,
        'baseline_sha256': baseline_sha256,
        'test_sha256': test_sha256,
        'baseline_filename': evidence['original_filename'],
        'test_filename': test_filename,
        'status_label': status_label,
        'explanation': explanation
    }
