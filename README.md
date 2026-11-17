# Digital Forensic Evidence Analyzer &bull; AI & Blockchain Edition

A college cybersecurity mini-project implementing a modern, web-based digital forensic investigation workstation. The application provides an interface for digital evidence ingestion, magic byte signature triage, chunked cryptographic hashing, metadata extraction, baseline integrity verification, **Proof-of-Work Blockchain Chain of Custody**, **AI Forensic Threat Triage**, and automated **ReportLab PDF Forensic Examination Report Generation**.

---

## Key Features & Main Modules

1. **Investigative Dashboard (`/`)**
   - Live operational metrics: Total evidence analyzed, total vault storage, blockchain block count, AI threats detected, and integrity verification matches.
   - Interactive charts (via Chart.js) depicting evidence category distribution and AI threat severity.
   - Fast-access table of recently ingested evidence with AI threat badges and blockchain block anchors.

2. **Evidence Ingestion & Vault Preservation (`/upload`)**
   - Non-destructive ingestion protocol: files are read-only streamed and preserved in `uploads/evidence/` with unique evidence UUIDs to eliminate overwrite collisions.
   - Strict read-only handling (`0o444`) to protect bitstream purity.
   - Intake fields for Case Reference Number, Lead Examiner name, and chain-of-custody notes.

3. **Cryptographic Blockchain Chain of Custody (`/blockchain`)**
   - **Immutable Proof-of-Work Ledger:** Every ingested evidence item is mined into an individual cryptographic block.
   - **Genesis Block Root:** Automatically initializes Block #0 as the root forensic anchor.
   - **Chain Linkage:** Each block incorporates `index_num`, `timestamp`, `evidence_id`, `case_number`, `file_hash` (SHA-256), `previous_hash`, and a mined `nonce` satisfying difficulty target prefix `"00"`.
   - **One-Click Blockchain Integrity Audit:** Validates every block from Genesis to Tip. If any record in the database is modified or tampered with by a rogue administrator, the hash link breaks and is instantly flagged.

4. **AI Forensic Threat Triage & Risk Scoring (`/evidence/<id>`)**
   - **Automated Anomaly Detection:** Evaluates extension masquerading, binary discrepancies, anti-forensics tools (Photoshop, ExifTool, GIMP), suspicious document producers, and malicious payload strings (`powershell`, `eval(`, `base64`, `DROP TABLE`).
   - **Risk Scoring (0 to 100):** Classifies artifacts into `LOW`, `ELEVATED`, `SUSPICIOUS`, or `CRITICAL THREAT`.
   - **AI Executive Summary & Recommendations:** Automatically generates natural language findings and recommends next steps for the forensic examiner (e.g. sandbox detonation, hex dump inspection, or physical geolocation cross-referencing).

5. **Multi-Algorithm File Analysis & Triage**
   - **Header Signature (Magic Bytes) Verification:** Inspects binary headers (JPEG, PNG, GIF, WEBP, BMP, TIFF, PDF, and UTF-8/ASCII plaintext) to identify extension tampering and spoofed attachments.
   - **Simultaneous Cryptographic Hashing:** Computes both **MD5** (128-bit) and **SHA-256** (256-bit) digests using chunked binary streams (64 KB buffers) via Python's standard `hashlib`.
   - **Deep Metadata Extraction:**
     - **Images (Pillow):** Image dimensions, color mode, EXIF camera tags (Make, Model, Software, Timestamps), and GPS Geolocation decoding (Latitude/Longitude conversion with Google Maps linkage).
     - **PDF Documents (pypdf):** Page counts, encryption state, and catalog metadata (Author, Creator, Producer, Creation Date).
     - **Text & Log Files:** Line count, word count, character count, newline convention analysis (CRLF vs. LF), and encoding detection.
   - **Filesystem Timestamps:** Host OS creation, modification, and access timestamps.

6. **Cryptographic File Integrity Verification (`/integrity`)**
   - Compare any active or newly acquired file against an established evidence item's recorded SHA-256 baseline.
   - Real-time bitstream comparison with high-visibility audit outcome banners:
     - `INTEGRITY VERIFIED: BITSTREAMS IDENTICAL` (Green)
     - `INTEGRITY BREACH / HASH MISMATCH DETECTED` (Red)
   - Persistent verification audit ledger recording dates, test filenames, and match results.

7. **Automated Forensic Report Generation (PDF)**
   - Generates official, court-ready **Forensic Examination Reports** using **ReportLab**.
   - Features case numbers, examiner credentials, technical file specifications, signature triage status, formatted MD5 and SHA-256 blocks, **Blockchain Proof-of-Custody Block Anchor**, **AI Forensic Threat Assessment**, metadata tables, and investigator sign-off blocks.
   - Includes mandatory forensic disclaimers and evidentiary limitation notices.

---

## Forensic Evidentiary Caveats & Disclaimers

The analyzer incorporates core forensic principles into both the user interface and generated PDF reports:
- **Baseline Integrity vs. Pre-Seizure Authenticity:** A matching SHA-256 cryptographic digest or valid blockchain block proves that the file has remained bit-for-bit identical since its intake into this system. It does **not** certify that the evidence was authentic, unmodified, or legitimate prior to acquisition.
- **Timestamp & Metadata Volatility:** Timestamps, EXIF headers, and document attributes are subject to manipulation, anti-forensics, and clock skews. They represent investigative leads, not absolute mathematical proof of origination.

---

## Technology Stack

- **Backend:** Python 3.12, Flask 3.1 (Blueprints, Application Factory)
- **Database:** SQLite 3 (Evidence records, verification audit logs, and blockchain ledger)
- **Forensic & Cryptographic Engine:** `hashlib` (MD5/SHA-256, Proof-of-Work blockchain hashing), `Pillow` (EXIF/GPS), `pypdf` (PDF metadata)
- **AI Triage Engine:** Multi-factor heuristic forensic risk scorer and natural language findings generator
- **Reporting Engine:** `ReportLab` (Platypus Flowable PDF documents)
- **Frontend:** Responsive HTML5, Vanilla JavaScript, Clean Light Forensic Theme (CSS3), Plus Jakarta Sans & JetBrains Mono, Chart.js

---

## Directory Structure

```text
Cyber security/
├── app/
│   ├── __init__.py                # Flask app factory, config & DB initialization
│   ├── config.py                  # Storage paths, upload limits, secret keys
│   ├── models/
│   │   ├── __init__.py
│   │   └── evidence.py            # SQLite schema, blockchain & audit queries
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── dashboard.py           # Dashboard analytics & metrics API
│   │   ├── evidence.py            # Ingestion, AI analysis triage, & history
│   │   ├── integrity.py           # Baseline vs live verification portal
│   │   ├── blockchain.py          # Blockchain ledger explorer & verification
│   │   └── reports.py             # ReportLab PDF report generation route
│   ├── services/
│   │   ├── __init__.py
│   │   ├── hasher.py              # Chunked MD5 & SHA-256 hashing
│   │   ├── validator.py           # Magic byte signature & spoof inspector
│   │   ├── metadata_extractor.py  # Pillow EXIF, PDF catalog & text stats
│   │   ├── integrity_service.py   # Baseline vs test file comparison
│   │   ├── blockchain.py          # Proof-of-Work blockchain engine & mining
│   │   ├── ai_analyzer.py         # AI threat evaluation & recommendations
│   │   └── report_generator.py    # ReportLab PDF document compiler
│   ├── static/
│   │   ├── css/
│   │   │   └── main.css           # Clean modern light forensic theme
│   │   └── js/
│   │       ├── dashboard.js       # Chart.js analytics logic
│   │       └── main.js            # Copy-to-clipboard & dropzone helpers
│   └── templates/
│       ├── base.html              # Navigation with Blockchain link
│       ├── dashboard.html         # Operational dashboard with AI & Block stats
│       ├── upload.html            # Evidence submission form
│       ├── evidence_detail.html   # File inspection, AI triage & Block anchor
│       ├── blockchain.html        # Blockchain explorer & chain audit portal
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
Execute the verification suite to validate database initialization, blockchain Proof-of-Work mining, tamper detection, AI threat scoring, hashing consistency, spoof detection, and PDF generation:
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
