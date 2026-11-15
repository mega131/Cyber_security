import os
import datetime
from pathlib import Path
from PIL import Image, ExifTags
import pypdf

def get_system_timestamps(file_path):
    """
    Retrieves operating system filesystem timestamps.
    Note: These reflect filesystem events on this host, not necessarily
    the original device timestamps, as emphasized by forensic standards.
    """
    stat = os.stat(file_path)
    return {
        'os_access_time': datetime.datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'os_modification_time': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'os_creation_time': datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S UTC'),
    }

def convert_to_degrees(value):
    """
    Helper function to convert GPS coordinates stored in EXIF (degrees, minutes, seconds)
    to decimal format.
    """
    try:
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None

def extract_image_metadata(file_path):
    """
    Extracts image specifications and embedded EXIF tags (including GPS) using Pillow.
    """
    meta = {
        'category': 'Image',
        'attributes': {},
        'exif': {},
        'gps': {}
    }
    
    try:
        with Image.open(file_path) as img:
            meta['attributes']['Dimensions'] = f"{img.width} x {img.height} pixels"
            meta['attributes']['Color Mode'] = img.mode
            meta['attributes']['Image Format'] = img.format or 'Unknown'
            if hasattr(img, 'is_animated'):
                meta['attributes']['Is Animated'] = 'Yes' if img.is_animated else 'No'
            if 'dpi' in img.info:
                meta['attributes']['Resolution (DPI)'] = f"{img.info['dpi'][0]} x {img.info['dpi'][1]}"
                
            # Extract raw EXIF if present
            raw_exif = img.getexif()
            if raw_exif:
                # Named EXIF tags
                for tag_id, value in raw_exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                    # Skip binary chunks or overly large blobs
                    if isinstance(value, (bytes, bytearray)) and len(value) > 64:
                        value = f"<Binary Data ({len(value)} bytes)>"
                    elif isinstance(value, tuple) and len(value) > 10:
                        value = f"<Tuple of {len(value)} items>"
                    meta['exif'][str(tag_name)] = str(value)
                    
                # Inspect IFD (Image File Directory) for detailed GPS
                try:
                    from PIL.ExifTags import IFD
                    gps_info = raw_exif.get_ifd(IFD.GPSInfo)
                    if gps_info:
                        gps_tags = {}
                        for k, v in gps_info.items():
                            sub_name = ExifTags.GPSTAGS.get(k, f"GPS_{k}")
                            gps_tags[sub_name] = v
                            
                        # Parse coordinates if latitude and longitude exist
                        lat = gps_tags.get('GPSLatitude')
                        lat_ref = gps_tags.get('GPSLatitudeRef')
                        lon = gps_tags.get('GPSLongitude')
                        lon_ref = gps_tags.get('GPSLongitudeRef')
                        
                        if lat and lat_ref and lon and lon_ref:
                            dec_lat = convert_to_degrees(lat)
                            dec_lon = convert_to_degrees(lon)
                            if dec_lat is not None and dec_lon is not None:
                                if str(lat_ref).upper() == 'S':
                                    dec_lat = -dec_lat
                                if str(lon_ref).upper() == 'W':
                                    dec_lon = -dec_lon
                                meta['gps']['Latitude'] = f"{dec_lat:.6f}° ({lat_ref})"
                                meta['gps']['Longitude'] = f"{dec_lon:.6f}° ({lon_ref})"
                                meta['gps']['Google Maps Link'] = f"https://www.google.com/maps?q={dec_lat},{dec_lon}"
                                
                        for gk, gv in gps_tags.items():
                            if gk not in ['GPSLatitude', 'GPSLongitude']:
                                meta['gps'][str(gk)] = str(gv)
                except Exception:
                    pass
    except Exception as e:
        meta['error'] = f"Error reading image metadata: {str(e)}"
        
    return meta

def extract_pdf_metadata(file_path):
    """
    Extracts PDF document properties, page count, and encryption info using pypdf.
    """
    meta = {
        'category': 'PDF Document',
        'attributes': {},
        'doc_info': {}
    }
    
    try:
        reader = pypdf.PdfReader(file_path)
        meta['attributes']['Page Count'] = len(reader.pages)
        meta['attributes']['Is Encrypted'] = 'Yes' if reader.is_encrypted else 'No'
        
        info = reader.metadata
        if info:
            for k, v in info.items():
                clean_key = k.lstrip('/')
                meta['doc_info'][clean_key] = str(v)
    except Exception as e:
        meta['error'] = f"Error parsing PDF metadata: {str(e)}"
        
    return meta

def extract_text_metadata(file_path):
    """
    Analyzes plaintext evidence, line terminations, word counts, and character statistics.
    """
    meta = {
        'category': 'Text Document',
        'attributes': {}
    }
    
    try:
        with open(file_path, 'rb') as f:
            raw = f.read()
            
        # Detect newline style
        if b'\r\n' in raw:
            newline_style = 'CRLF (Windows standard)'
        elif b'\n' in raw:
            newline_style = 'LF (Unix/Linux standard)'
        elif b'\r' in raw:
            newline_style = 'CR (Legacy Macintosh)'
        else:
            newline_style = 'Single line / None'
            
        meta['attributes']['Line Termination'] = newline_style
        
        # Try decoding
        decoded_text = None
        encoding_used = 'Unknown'
        for enc in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
            try:
                decoded_text = raw.decode(enc)
                encoding_used = enc.upper()
                break
            except UnicodeDecodeError:
                continue
                
        meta['attributes']['Detected Encoding'] = encoding_used
        
        if decoded_text is not None:
            lines = decoded_text.splitlines()
            words = decoded_text.split()
            meta['attributes']['Total Characters'] = len(decoded_text)
            meta['attributes']['Total Lines'] = len(lines)
            meta['attributes']['Total Words'] = len(words)
            non_empty_lines = [l for l in lines if l.strip()]
            meta['attributes']['Non-Empty Lines'] = len(non_empty_lines)
            meta['attributes']['Preview'] = decoded_text[:500] + ('...' if len(decoded_text) > 500 else '')
    except Exception as e:
        meta['error'] = f"Error analyzing text document: {str(e)}"
        
    return meta

def extract_metadata(file_path, detected_mime):
    """
    Master metadata dispatcher based on detected MIME / signature.
    """
    timestamps = get_system_timestamps(file_path)
    
    if detected_mime.startswith('image/'):
        result = extract_image_metadata(file_path)
    elif detected_mime == 'application/pdf':
        result = extract_pdf_metadata(file_path)
    elif detected_mime.startswith('text/') or detected_mime in ['application/json', 'application/xml']:
        result = extract_text_metadata(file_path)
    else:
        result = {
            'category': 'Generic Binary',
            'attributes': {'Notice': 'Specialized metadata parsing is not supported for this raw binary format.'}
        }
        
    result['timestamps'] = timestamps
    return result
