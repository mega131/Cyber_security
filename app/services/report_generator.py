import io
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

def build_pdf_report(evidence_data):
    """
    Constructs an official, forensic-grade PDF report using ReportLab.
    Returns a BytesIO stream containing the generated PDF binary.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Palette
    COLOR_PRIMARY = colors.HexColor('#0F172A')    # Slate dark
    COLOR_SECONDARY = colors.HexColor('#0284C7')  # Forensic cyan
    COLOR_ACCENT = colors.HexColor('#0369A1')     # Deep azure
    COLOR_TEXT = colors.HexColor('#1E293B')       # Body text
    COLOR_MUTED = colors.HexColor('#64748B')      # Subtitle/muted
    COLOR_LIGHT_BG = colors.HexColor('#F8FAFC')   # Table light bg
    COLOR_BORDER = colors.HexColor('#CBD5E1')     # Clean border
    COLOR_ALERT = colors.HexColor('#DC2626')      # Red alert
    COLOR_SUCCESS = colors.HexColor('#16A34A')    # Green ok
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=COLOR_PRIMARY,
        alignment=TA_LEFT
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=COLOR_SECONDARY,
        alignment=TA_LEFT
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=COLOR_PRIMARY,
        spaceBefore=12,
        spaceAfter=6
    )
    
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=COLOR_PRIMARY
    )
    
    cell_value = ParagraphStyle(
        'CellValue',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=COLOR_TEXT
    )
    
    mono_style = ParagraphStyle(
        'MonoHash',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=COLOR_PRIMARY
    )
    
    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=COLOR_TEXT,
        alignment=TA_JUSTIFY
    )
    
    story = []
    
    # Header Banner Table
    header_data = [
        [
            Paragraph("DIGITAL FORENSIC EVIDENCE ANALYZER", subtitle_style),
            Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", ParagraphStyle('HeadRight', parent=styles['Normal'], fontName='Helvetica', fontSize=8, textColor=COLOR_MUTED, alignment=TA_RIGHT))
        ],
        [
            Paragraph("FORENSIC EXAMINATION & INTEGRITY REPORT", title_style),
            Paragraph(f"Evidence ID: <b>{evidence_data.get('evidence_id', 'N/A')}</b>", ParagraphStyle('IdRight', parent=styles['Normal'], fontName='Helvetica', fontSize=9, textColor=COLOR_PRIMARY, alignment=TA_RIGHT))
        ]
    ]
    header_table = Table(header_data, colWidths=[350, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('TOPPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=2, color=COLOR_SECONDARY, spaceBefore=2, spaceAfter=12))
    
    # Case & Examiner Summary
    story.append(Paragraph("1. CASE & CHAIN OF CUSTODY INFORMATION", section_heading))
    case_info = [
        [Paragraph("Case Number:", cell_bold), Paragraph(str(evidence_data.get('case_number', 'CASE-DEFAULT')), cell_value),
         Paragraph("Examiner:", cell_bold), Paragraph(str(evidence_data.get('examiner_name', 'Forensic Analyst')), cell_value)],
        [Paragraph("Ingestion Timestamp:", cell_bold), Paragraph(str(evidence_data.get('created_at', 'N/A')), cell_value),
         Paragraph("Storage Vault Ref:", cell_bold), Paragraph(str(evidence_data.get('stored_filename', 'N/A')), cell_value)]
    ]
    t_case = Table(case_info, colWidths=[120, 145, 120, 145])
    t_case.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), COLOR_LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_case)
    story.append(Spacer(1, 10))
    
    # Evidence File Technical Profile
    story.append(Paragraph("2. EVIDENCE ITEM SPECIFICATIONS & SIGNATURE ANALYSIS", section_heading))
    sig_status = evidence_data.get('signature_status', 'UNKNOWN')
    sig_color = COLOR_SUCCESS if sig_status == 'MATCH' else (COLOR_ALERT if sig_status == 'MISMATCH' else COLOR_MUTED)
    
    file_specs = [
        [Paragraph("Original Filename:", cell_bold), Paragraph(str(evidence_data.get('original_filename', 'N/A')), cell_value)],
        [Paragraph("File Size:", cell_bold), Paragraph(f"{evidence_data.get('file_size_formatted', '0 B')} ({evidence_data.get('file_size_bytes', 0):,} bytes)", cell_value)],
        [Paragraph("Declared Extension / MIME:", cell_bold), Paragraph(f".{evidence_data.get('file_extension', '')} / {evidence_data.get('declared_mime', 'N/A')}", cell_value)],
        [Paragraph("Detected Format / MIME:", cell_bold), Paragraph(f"<b>{evidence_data.get('detected_type_label', 'N/A')}</b> ({evidence_data.get('detected_mime', 'N/A')})", cell_value)],
        [Paragraph("Signature Integrity Check:", cell_bold), Paragraph(f"<font color='{sig_color.hexval()}'><b>{sig_status}</b></font> - {evidence_data.get('signature_details', '')}", cell_value)]
    ]
    t_specs = Table(file_specs, colWidths=[150, 380])
    t_specs.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), COLOR_LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_specs)
    story.append(Spacer(1, 10))
    
    # Cryptographic Hash Signatures
    story.append(Paragraph("3. CRYPTOGRAPHIC INTEGRITY DIGESTS (BASELINE)", section_heading))
    hash_data = [
        [Paragraph("Algorithm", cell_bold), Paragraph("Cryptographic Hash Digest", cell_bold)],
        [Paragraph("<b>MD5</b> (128-bit)", cell_value), Paragraph(str(evidence_data.get('md5_hash', 'N/A')), mono_style)],
        [Paragraph("<b>SHA-256</b> (256-bit)", cell_value), Paragraph(str(evidence_data.get('sha256_hash', 'N/A')), mono_style)],
    ]
    t_hash = Table(hash_data, colWidths=[120, 410])
    t_hash.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLOR_LIGHT_BG),
        ('BOX', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_hash)
    story.append(Spacer(1, 10))
    
    # Metadata Details
    meta = evidence_data.get('metadata')
    if not meta and evidence_data.get('metadata_json'):
        try:
            meta = json.loads(evidence_data['metadata_json'])
        except Exception:
            meta = {}
            
    if meta:
        story.append(Paragraph("4. EXTRACTED METADATA & FORENSIC ARTIFACTS", section_heading))
        meta_rows = []
        
        # Attributes
        if meta.get('attributes'):
            for k, v in meta['attributes'].items():
                if k == 'Preview':
                    continue
                meta_rows.append([Paragraph(str(k), cell_bold), Paragraph(str(v), cell_value)])
                
        # EXIF Tags
        if meta.get('exif'):
            for k, v in list(meta['exif'].items())[:12]:  # Limit top 12 EXIF tags for readability
                meta_rows.append([Paragraph(f"EXIF: {k}", cell_bold), Paragraph(str(v), cell_value)])
                
        # GPS
        if meta.get('gps'):
            for k, v in meta['gps'].items():
                meta_rows.append([Paragraph(f"GPS: {k}", cell_bold), Paragraph(str(v), cell_value)])
                
        # PDF Doc Info
        if meta.get('doc_info'):
            for k, v in meta['doc_info'].items():
                meta_rows.append([Paragraph(f"Doc: {k}", cell_bold), Paragraph(str(v), cell_value)])
                
        # Timestamps
        if meta.get('timestamps'):
            for k, v in meta['timestamps'].items():
                clean_k = k.replace('_', ' ').title()
                meta_rows.append([Paragraph(f"FS: {clean_k}", cell_bold), Paragraph(str(v), cell_value)])
                
        if meta_rows:
            t_meta = Table(meta_rows, colWidths=[150, 380])
            t_meta.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), COLOR_LIGHT_BG),
                ('BOX', (0,0), (-1,-1), 0.5, COLOR_BORDER),
                ('INNERGRID', (0,0), (-1,-1), 0.5, COLOR_BORDER),
                ('TOPPADDING', (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t_meta)
            story.append(Spacer(1, 10))
            
    # Forensic Limitations and Disclaimers
    story.append(Paragraph("5. FORENSIC LIMITATIONS & METHODOLOGICAL DISCLAIMERS", section_heading))
    disclaimer_text = (
        "<b>A. Cryptographic Baseline Integrity:</b> The hash digests recorded in Section 3 represent the "
        "bitstream state of the evidence item strictly upon intake into this analyzer. A matching SHA-256 digest "
        "validates that the digital artifact has remained intact without bit-level modification since ingestion. "
        "A matching hash does <i>not</i> prove that the file was genuine, authentic, or unmanipulated prior to its "
        "forensic acquisition.<br/><br/>"
        "<b>B. Metadata and Timestamp Reliability:</b> Extracted filesystem timestamps, EXIF tags, and document "
        "properties are provided for investigative context. Timestamps are subject to clock skew, timezone "
        "discrepancies, and anti-forensic modification. They do not constitute conclusive mathematical proof of "
        "authorship or origination without corroborating environmental artifacts."
    )
    
    t_disclaimer = Table([[Paragraph(disclaimer_text, disclaimer_style)]], colWidths=[530])
    t_disclaimer.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
        ('BOX', (0,0), (-1,-1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_disclaimer)
    story.append(Spacer(1, 15))
    
    # Examiner Sign-off
    signoff = [
        [
            Paragraph("<b>Analyst Signature:</b> ___________________________", cell_value),
            Paragraph("<b>Lab Verification Seal:</b> [ VERIFIED RECORD ]", cell_value)
        ]
    ]
    t_sign = Table(signoff, colWidths=[280, 250])
    t_sign.setStyle(TableStyle([
        ('TOPPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(KeepTogether(t_sign))
    
    doc.build(story)
    buffer.seek(0)
    return buffer
