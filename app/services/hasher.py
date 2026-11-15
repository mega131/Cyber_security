import hashlib

def calculate_hashes(file_path, chunk_size=65536):
    """
    Computes both MD5 and SHA-256 digests simultaneously
    in 64KB chunks to maintain memory efficiency and read-only streaming.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha256.update(chunk)
            
    return {
        'md5': md5.hexdigest().lower(),
        'sha256': sha256.hexdigest().lower()
    }

def calculate_stream_sha256(stream, chunk_size=65536):
    """
    Calculates SHA-256 for an in-memory or incoming file stream
    without saving it to disk.
    """
    sha256 = hashlib.sha256()
    stream.seek(0)
    while chunk := stream.read(chunk_size):
        sha256.update(chunk)
    stream.seek(0)
    return sha256.hexdigest().lower()
