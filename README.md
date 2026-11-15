# Digital Forensic Evidence Analyzer

A college cybersecurity mini-project implementing a web-based digital forensic investigation workstation. The application provides an interface for digital evidence ingestion, magic byte signature triage, chunked cryptographic hashing, metadata extraction, baseline integrity verification, and automated ReportLab PDF forensic report generation.

---

## Key Features & Main Modules

1. **Investigative Dashboard**
   - Live metrics on total evidence items analyzed and storage vault volume.
   - Interactive charts (via Chart.js) depicting evidence distribution by file category and integrity audit outcomes.
   - Comprehensive overview of supported forensic formats.
   - Fast-access table of recently ingested evidence.

2. **Evidence Ingestion & Vault Preservation**
   - Non-destructive ingestion protocol: files are read-only streamed and preserved in `uploads/evidence/` with unique evidence UUIDs to eliminate overwrite collisions.
   - Strict read-only handling (`0o444`) to protect bitstream purity.
   - Intake fields for Case Reference Number, Lead Examiner name, and chain-of-custody notes.

3. **Multi-Algorithm File Analysis & Triage**
   - **Header Signature (Magic Bytes) Verification:** Inspects binary headers (JPEG, PNG, GIF, WEBP, BMP, TIFF, PDF, and UTF-8/ASCII plaintext) to identify extension tampering and spoofed attachments.
   - **Simultaneous Cryptographic Hashing:** Computes both **MD5** (128-bit) and **SHA-256** (256-bit) digests using chunked binary streams (64 KB buffers) via Python's standard `hashlib`.
   - **Deep Metadata Extraction:**
     - **Images (Pillow):** Image dimensions, color mode, EXIF camera tags (Make, Model, Software, Timestamps), and GPS Geolocation decoding (Latitude/Longitude conversion with Google Maps linkage).
     - **PDF Documents (pypdf):** Page counts, encryption state, and catalog metadata (Author, Creator, Producer, Creation Date).
     - **Text & Log Files:** Line count, word count, character count, newline convention analysis (CRLF vs. LF), and encoding detection.
   - **Filesystem Timestamps:** Host OS creation, modification, and access timestamps.

4. **Cryptographic File Integrity Verification**
   - Compare any active or newly acquired file against an established evidence item's recorded SHA-256 baseline.
   - Real-time bitstream comparison with high-visibility audit outcome banners:
     - `INTEGRITY VERIFIED: BITSTREAMS IDENTICAL` (Green)
     - `INTEGRITY BREACH / HASH MISMATCH DETECTED` (Red)
   - Persistent verification audit ledger recording dates, test filenames, and match results.

5. **Evidence History & Repository Ledger**
   - Searchable, filterable repository powered by SQLite (`data/forensic.db`).
   - Query by Evidence ID, original filename, case number, or SHA-256 hash.
   - Filter by evidence type (Images, PDFs, Plaintext).
   - One-click copy buttons for long cryptographic digests.

6. **Automated Forensic Report Generation (PDF)**
   - Generates official, court-ready **Forensic Examination Reports** using **ReportLab**.
   - Features case numbers, examiner credentials, technical file specifications, signature triage status, formatted MD5 and SHA-256 blocks, metadata tables, and investigator sign-off blocks.
   - Includes mandatory forensic disclaimers and evidentiary limitation notices.

---

## Forensic Evidentiary Caveats & Disclaimers

The analyzer incorporates core forensic principles into both the user interface and generated PDF reports:
- **Baseline Integrity vs. Pre-Seizure Authenticity:** A matching SHA-256 cryptographic digest proves that the file has remained bit-for-bit identical since its intake into this system. It does **not** certify that the evidence was authentic, unmodified, or legitimate prior to acquisition.
- **Timestamp & Metadata Volatility:** Timestamps, EXIF headers, and document attributes are subject to manipulation, anti-forensics, and clock skews. They represent investigative leads, not absolute mathematical proof of origination.

---

## Technology Stack

- **Backend:** Python 3.12, Flask 3.1 (Blueprints, Application Factory)
- **Database:** SQLite 3 (Lightweight, zero-configuration local ledger)
- **Forensic & Cryptographic Engine:** `hashlib` (MD5/SHA-256), `Pillow` (EXIF/GPS), `pypdf` (PDF metadata)
- **Reporting Engine:** `ReportLab` (Custom Flowable PDF documents)
- **Frontend:** Responsive HTML5, Vanilla JavaScript, Custom Dark Forensic Theme (CSS3), Chart.js

---

## Directory Structure

```text
Cyber security/
├── app/
│   ├── __init__.py                # Flask app factory, config & DB initialization
│   ├── config.py                  # Storage paths, upload limits, secret keys
│   ├── models/
│   │   ├── __init__.py
│   │   └── evidence.py            # SQLite schema, queries & audit logging
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── dashboard.py           # Dashboard views & analytics API
│   │   ├── evidence.py            # Intake, analysis detail, & history search
│   │   ├── integrity.py           # Integrity comparison engine & audit logs
│   │   └── reports.py             # ReportLab PDF report generation route
│   ├── services/
│   │   ├── __init__.py
│   │   ├── hasher.py              # Chunked MD5 & SHA-256 hashing
│   │   ├── validator.py           # Magic byte signature & spoof inspector
│   │   ├── metadata_extractor.py  # Pillow EXIF, PDF catalog & text stats
│   │   ├── integrity_service.py   # Baseline vs test file comparison
│   │   └── report_generator.py    # ReportLab document compiler
│   ├── static/
│   │   ├── css/
│   │   │   └── main.css           # Dark cybersecurity forensic theme
│   │   └── js/
│   │       ├── dashboard.js       # Chart.js metrics setup
│   │       └── main.js            # Copy-to-clipboard & dropzone helpers
│   └── templates/
│       ├── base.html              # Core navigation & forensic UI layout
│       ├── dashboard.html         # Analytics dashboard & quick metrics
│       ├── upload.html            # Evidence submission form
│       ├── evidence_detail.html   # Detailed file inspection & metadata view
│       ├── history.html           # Searchable evidence repository table
│       └── integrity.html         # Integrity verification portal & logs
├── data/
│   └── forensic.db                # SQLite database (auto-generated)
├── uploads/
│   └── evidence/                  # Evidence vault directory (read-only)
├── tests/
│   └── test_suite.py              # Automated unit & integration tests
├── requirements.txt               # Python package dependencies
├── run.py                         # Application execution entrypoint
└── README.md                      # Documentation & forensic guide
```

---

## Installation & Setup

### 1. Prerequisites
Ensure Python 3.10+ is installed on your system.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Automated Tests
Execute the verification suite to validate database initialization, hashing consistency, spoof detection, and PDF generation:
```bash
python -m unittest tests/test_suite.py
```

### 4. Start the Application
```bash
python run.py
```
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## How to Test the Application

1. **Ingest an Evidence File:**
   - Go to **Evidence Ingestion** (`/upload`).
   - Drag and drop any image (`.jpg`, `.png`), document (`.pdf`), or log file (`.txt`).
   - Provide a Case Number (e.g. `CASE-2026-001`) and Investigator name.
   - Click **Ingest & Perform Forensic Analysis**.

2. **Inspect the Evidence Details:**
   - Review the detected MIME type, magic byte match status, and host filesystem timestamps.
   - Inspect the MD5 and SHA-256 digests. Use the **Copy** button to copy hashes to your clipboard.
   - Examine the extracted EXIF tags, GPS links, or PDF properties.
   - Click **Download Forensic Report (PDF)** to download an examination document.

3. **Verify File Integrity:**
   - Go to **Integrity Verification** (`/integrity`).
   - Select the ingested evidence item from the dropdown.
   - Upload the identical file: observe the green **INTEGRITY VERIFIED: BITSTREAMS IDENTICAL** banner.
   - Open a text editor, alter one character in the file, save it as a new copy, and upload it: observe the red **INTEGRITY BREACH / HASH MISMATCH DETECTED** banner.
   - Check the **Verification Audit Log** at the bottom of the page.

4. **Test Extension Spoof Detection:**
   - Create a text file `secret.txt` containing text.
   - Rename `secret.txt` to `fake_photo.jpg`.
   - Ingest `fake_photo.jpg` into the analyzer.
   - Notice the high-visibility warning banner: **FILE SIGNATURE ANOMALY DETECTED (POTENTIAL SPOOFING)** because the magic header is ASCII/UTF-8 plaintext while the declared extension was `.jpg`.
