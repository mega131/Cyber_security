import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'forensic-secure-investigator-key-2026')
    BASE_DIR = BASE_DIR
    UPLOAD_FOLDER = BASE_DIR / 'uploads' / 'evidence'
    DATA_FOLDER = BASE_DIR / 'data'
    DATABASE_PATH = DATA_FOLDER / 'forensic.db'
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB max file size
    ALLOWED_EXTENSIONS = {
        # Images
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff',
        # Documents
        'pdf',
        # Plaintext & Code
        'txt', 'log', 'csv', 'json', 'md', 'xml'
    }
