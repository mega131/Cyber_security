import os
from pathlib import Path

MAGIC_SIGNATURES = [
    {
        'label': 'JPEG Image',
        'mime': 'image/jpeg',
        'extensions': ['jpg', 'jpeg'],
        'check': lambda b: b.startswith(b'\xff\xd8\xff')
    },
    {
        'label': 'PNG Image',
        'mime': 'image/png',
        'extensions': ['png'],
        'check': lambda b: b.startswith(b'\x89PNG\r\n\x1a\n')
    },
    {
        'label': 'GIF Image',
        'mime': 'image/gif',
        'extensions': ['gif'],
        'check': lambda b: b.startswith(b'GIF87a') or b.startswith(b'GIF89a')
    },
    {
        'label': 'WEBP Image',
        'mime': 'image/webp',
        'extensions': ['webp'],
        'check': lambda b: len(b) >= 12 and b[:4] == b'RIFF' and b[8:12] == b'WEBP'
    },
    {
        'label': 'BMP Image',
        'mime': 'image/bmp',
        'extensions': ['bmp'],
        'check': lambda b: b.startswith(b'BM')
    },
    {
        'label': 'TIFF Image',
        'mime': 'image/tiff',
        'extensions': ['tif', 'tiff'],
        'check': lambda b: b.startswith(b'II*\x00') or b.startswith(b'MM\x00*')
    },
    {
        'label': 'PDF Document',
        'mime': 'application/pdf',
        'extensions': ['pdf'],
        'check': lambda b: b.startswith(b'%PDF-')
    }
]

def is_text_file(header_sample):
    """
    Checks if binary sample represents readable plaintext without binary null bytes.
    """
    if not header_sample:
        return True
    if b'\x00' in header_sample:
        return False
    try:
        header_sample.decode('utf-8')
        return True
    except UnicodeDecodeError:
        try:
            header_sample.decode('latin-1')
            return True
        except UnicodeDecodeError:
            return False

def inspect_file_signature(file_path, declared_filename):
    """
    Examines file header magic bytes and cross-references with the declared filename extension.
    Returns:
        dict: {
            'detected_label': str,
            'detected_mime': str,
            'status': 'MATCH' | 'MISMATCH' | 'GENERIC_TEXT' | 'UNKNOWN',
            'details': str
        }
    """
    path = Path(file_path)
    ext = path.suffix.lower().lstrip('.')
    if declared_filename:
        declared_ext = declared_filename.rsplit('.', 1)[-1].lower() if '.' in declared_filename else ''
    else:
        declared_ext = ext
        
    with open(file_path, 'rb') as f:
        header = f.read(512)
        
    # Check binary signatures first
    for sig in MAGIC_SIGNATURES:
        if sig['check'](header):
            detected_label = sig['label']
            detected_mime = sig['mime']
            
            if declared_ext in sig['extensions']:
                return {
                    'detected_label': detected_label,
                    'detected_mime': detected_mime,
                    'status': 'MATCH',
                    'details': f'Header signature verified ({header[:8].hex(" ").upper()}). Matches declared extension ".{declared_ext}".'
                }
            else:
                return {
                    'detected_label': detected_label,
                    'detected_mime': detected_mime,
                    'status': 'MISMATCH',
                    'details': f'ANOMALY DETECTED: Header signature is {detected_label} ({detected_mime}), but declared extension is ".{declared_ext}". Potential extension spoofing.'
                }
                
    # Check if it is plaintext
    if is_text_file(header):
        text_exts = ['txt', 'log', 'csv', 'json', 'md', 'xml', 'py', 'c', 'cpp', 'html', 'js']
        if declared_ext in text_exts:
            return {
                'detected_label': 'Plain Text / Structured Document',
                'detected_mime': 'text/plain',
                'status': 'MATCH',
                'details': f'Valid plaintext encoding verified. Declared extension ".{declared_ext}" is consistent.'
            }
        else:
            return {
                'detected_label': 'Plain Text Document',
                'detected_mime': 'text/plain',
                'status': 'MISMATCH',
                'details': f'ANOMALY DETECTED: File contains ASCII/UTF-8 plaintext, but declared extension is ".{declared_ext}". Potential extension spoofing.'
            }
            
    return {
        'detected_label': 'Unknown Binary Stream',
        'detected_mime': 'application/octet-stream',
        'status': 'UNKNOWN',
        'details': f'Unrecognized file header signature ({header[:8].hex(" ").upper()}).'
    }
