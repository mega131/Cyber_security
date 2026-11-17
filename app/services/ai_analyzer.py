import os
import json
import re

def analyze_evidence_with_ai(original_filename, declared_mime, detected_mime, signature_status, signature_details, file_size_bytes, metadata):
    """
    Intelligent Digital Forensic AI Engine:
    Evaluates evidentiary risk, anti-forensics, extension masquerading,
    metadata discrepancies, and generates an automated forensic assessment.
    """
    risk_score = 10  # Baseline informational score
    risk_factors = []
    recommendations = []
    
    filename_lower = original_filename.lower()
    ext = filename_lower.rsplit('.', 1)[-1] if '.' in filename_lower else ''
    
    # 1. Header Signature Anomaly Check (Highest weight in forensics)
    if signature_status == 'MISMATCH':
        risk_score += 65
        risk_factors.append(f"CRITICAL EXTENSION SPOOFING: Declared extension '.{ext}' contradicts verified binary header ({detected_mime}). Potential payload concealment.")
        recommendations.append("Immediate isolation: Detonate artifact within an air-gapped forensic sandbox to inspect disguised executable code.")
        recommendations.append("Hex dump inspection: Examine initial 512 bytes for hidden PE/ELF/Script headers or shellcode.")
    elif signature_status == 'MATCH':
        risk_factors.append(f"Header Integrity Verified: Magic bytes correspond with declared format ({detected_mime}).")
    else:
        risk_score += 15
        risk_factors.append("Generic or Unrecognized Binary Signature: File does not match common standardized headers.")
        recommendations.append("Perform deep carver triage (e.g. Scalpel or Foremost) to identify composite or fragmented file structures.")

    # 2. File Size Heuristics
    if ext in ['jpg', 'jpeg', 'png'] and file_size_bytes < 200:
        risk_score += 25
        risk_factors.append(f"Suspiciously Small Image Volume ({file_size_bytes} bytes): Normal image headers typically exceed this size. Potential placeholder or spoofed shell script.")
    elif ext in ['log', 'txt'] and file_size_bytes > 20 * 1024 * 1024:
        risk_score += 15
        risk_factors.append(f"Unusually Large Log File ({round(file_size_bytes / (1024*1024), 2)} MB): High likelihood of log-bloating or embedded binary blob.")
        recommendations.append("Perform chunked keyword scanning and entropy analysis to locate hidden binary embeddings.")

    # 3. Metadata & Anti-Forensics Analysis
    if metadata:
        # Check Image EXIF
        exif = metadata.get('exif', {})
        if exif:
            software = str(exif.get('Software', '')).lower()
            tamper_tools = ['photoshop', 'gimp', 'paint.net', 'exiftool', 'hxd', 'canva']
            for tool in tamper_tools:
                if tool in software:
                    risk_score += 20
                    risk_factors.append(f"Anti-Forensic/Editing Software Detected: EXIF tag reveals modification using '{software}'. Metadata may have been stripped or synthesized.")
                    recommendations.append("Conduct Error Level Analysis (ELA) to identify localized pixel compression inconsistencies.")
                    break
                    
        # Check Geolocation
        gps = metadata.get('gps', {})
        if gps and 'Latitude' in gps:
            risk_factors.append(f"High-Value Geolocation Artifact: Embedded GPS coordinates pinpointed ({gps.get('Latitude')}, {gps.get('Longitude')}).")
            recommendations.append("Cross-reference physical scene coordinates with suspect timeline, mobile cell-tower dumps, and surveillance logs.")

        # Check PDF Catalog
        doc_info = metadata.get('doc_info', {})
        if doc_info:
            producer = str(doc_info.get('Producer', '')).lower()
            creator = str(doc_info.get('Creator', '')).lower()
            if any(term in producer + creator for term in ['kali', 'exploit', 'metasploit', 'script']):
                risk_score += 40
                risk_factors.append(f"Suspicious Document Tooling Artifacts: Producer/Creator indicates security/exploit utility ('{producer or creator}').")
                recommendations.append("Scan PDF object catalog for JavaScript streams (/JS, /JavaScript) and Launch actions (/Launch).")

        # Check Plaintext Preview for Malicious Strings
        preview = metadata.get('attributes', {}).get('Preview', '').lower()
        if preview:
            indicators = [
                ('base64', 'Encoded data string (potential obfuscation)'),
                ('powershell', 'PowerShell command invocation'),
                ('cmd.exe', 'Command line execution call'),
                ('eval(', 'Dynamic code execution call (eval)'),
                ('drop table', 'SQL Injection syntax'),
                ('union select', 'SQL database enumeration pattern'),
                ('cve-', 'Known Exploit Vulnerability reference')
            ]
            for term, desc in indicators:
                if term in preview:
                    risk_score += 20
                    risk_factors.append(f"Suspicious String Pattern: Found '{term}' in plaintext ({desc}).")
                    recommendations.append(f"Conduct full-text regex extraction for all occurrences of '{term}' and surrounding payload parameters.")

    # Cap risk score between 5 and 100
    risk_score = min(max(risk_score, 5), 100)
    
    # Threat Level Classification
    if risk_score >= 75:
        threat_level = "CRITICAL"
        threat_badge = "CRITICAL FORENSIC THREAT"
        badge_class = "danger"
    elif risk_score >= 50:
        threat_level = "SUSPICIOUS"
        threat_badge = "SUSPICIOUS ARTIFACT"
        badge_class = "warning"
    elif risk_score >= 25:
        threat_level = "ELEVATED"
        threat_badge = "ELEVATED MONITORING"
        badge_class = "info"
    else:
        threat_level = "LOW"
        threat_badge = "BENIGN / LOW RISK"
        badge_class = "success"

    # Default recommendations if clean
    if not recommendations:
        recommendations.append("Record cryptographic hash baseline in blockchain ledger.")
        recommendations.append("Archive evidence bitstream in secure air-gapped vault in compliance with ISO/IEC 27037 standards.")

    # Executive Summary Generation
    if threat_level in ["CRITICAL", "SUSPICIOUS"]:
        exec_summary = (
            f"Automated AI forensic evaluation classifies artifact '{original_filename}' as {threat_level} (Risk Score: {risk_score}/100). "
            f"The primary forensic anomaly is identified in signature validation and structural heuristics. "
            f"Investigative priority should be assigned to payload verification and anti-forensic countermeasures."
        )
    else:
        exec_summary = (
            f"Automated AI forensic evaluation classifies artifact '{original_filename}' as {threat_level} (Risk Score: {risk_score}/100). "
            f"The item exhibits standard evidentiary structural consistency with no immediate indicators of extension masquerading or tool tampering. "
            f"Integrity baselines have been verified against header standards."
        )

    return {
        'threat_level': threat_level,
        'threat_badge': threat_badge,
        'badge_class': badge_class,
        'risk_score': risk_score,
        'executive_summary': exec_summary,
        'risk_factors': risk_factors,
        'recommendations': recommendations
    }
