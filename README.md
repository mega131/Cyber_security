# Digital Forensic Evidence Analyzer
### *AI-Powered & Cryptographic Blockchain Edition*

A comprehensive, web-based digital forensic investigation workstation designed as an academic cybersecurity capstone project. The platform integrates **Non-Destructive Evidence Ingestion**, **Header Magic Byte Verification**, **Chunked Cryptographic Hashing**, **Deep Metadata/EXIF/GPS Extraction**, **Proof-of-Work Blockchain Chain of Custody**, **AI Forensic Threat Triage**, and automated **Court-Admissible PDF Examination Report Generation**.

---

## Table of Contents
1. [Why Do We Need This Project? (Problem Statement)](#1-why-do-we-need-this-project-problem-statement)
2. [End-to-End System Workflow (The 4-Step Pipeline)](#2-end-to-end-system-workflow-the-4-step-pipeline)
3. [The Blockchain Concept Explained (How It Works Under the Hood)](#3-the-blockchain-concept-explained-how-it-works-under-the-hood)
4. [AI Forensic Threat Analysis Engine](#4-ai-forensic-threat-analysis-engine)
5. [Automated Forensic Report Generation (ReportLab PDF)](#5-automated-forensic-report-generation-reportlab-pdf)
6. [Forensic Evidentiary Disclaimers & Legal Caveats](#6-forensic-evidentiary-disclaimers--legal-caveats)
7. [Technology Stack](#7-technology-stack)
8. [Project Architecture & Directory Structure](#8-project-architecture--directory-structure)
9. [Installation & Setup](#9-installation--setup)
10. [Testing & Live Demonstration Guide](#10-testing--live-demonstration-guide)
11. [College Viva & Presentation Q&A Preparation](#11-college-viva--presentation-qa-preparation)

---

## 1. Why Do We Need This Project? (Problem Statement)

When presenting this project, start with the core challenges of digital evidence:

* **Digital Evidence is Inherently Volatile:** Unlike physical evidence (e.g., fingerprints or ballistics), digital artifacts (files, images, server logs, documents) can be altered, fabricated, or backdated with a single click without leaving visible marks.
* **The Legal Challenge (Court Admissibility & Chain of Custody):** In forensic jurisprudence, digital evidence is admissible in court only if the investigator can mathematically prove an unbroken **Chain of Custody**—proving that the evidence presented at trial is *100% bitstream-identical* to the evidence seized at the scene.
* **The Insider Threat & Centralized Database Vulnerability:** Traditional systems store evidence records in standard SQL databases (MySQL, SQLite). Anyone with database administrator (DBA) access or a compromised SQL server can silently alter records (`UPDATE evidence SET sha256_hash = '...'`). There is no cryptographic proof that the database itself was not altered.
* **File Extension Spoofing:** Cybercriminals routinely disguise payloads (e.g. renaming executable malware or stolen text to `.jpg` or `.pdf`) to bypass security filters.

**Our Solution:** An automated workstation that ingests evidence non-destructively, identifies spoofed extensions via binary magic bytes, computes dual cryptographic hashes, triages risks with an AI engine, anchors records into an immutable **Proof-of-Work Blockchain**, and produces court-admissible PDF reports.

---

## 2. End-to-End System Workflow (The 4-Step Pipeline)

The system operates as an integrated forensic pipeline:

```
[ Step 1: Ingestion ] ➔ [ Step 2: Forensic Triage ] ➔ [ Step 3: Ledger & Chain ] ➔ [ Step 4: Verification & PDF ]
  • Case / Examiner       • Magic Byte Check            • SQLite Database               • Match / Mismatch
  • Read-Only Vault       • Dual Hashing (MD5/SHA256)   • Proof-of-Work Block           • ReportLab PDF Export
  • UUID Assignment       • Metadata (EXIF/GPS/PDF)     • AI Threat Scoring
```

### Step 1: Non-Destructive Ingestion (`/upload`)
* Investigator uploads an evidence artifact with Case Number, Examiner Name, and Intake Notes.
* **Forensic Principle:** The original file must never be modified. The backend generates a timestamped UUID (`EVD-YYYYMMDD-XXXXXXXX`), saves it to an isolated vault directory (`uploads/evidence/`), and locks it with **read-only permissions** (`0o444`).

### Step 2: Deep Forensic Triage & Hashing
Simultaneously executes three analysis engines:
1. **Magic Byte Signature Inspection (`app/services/validator.py`):**
   * Inspects the file's raw binary header bytes rather than trusting its declared extension.
   * If a file declared as `.jpg` begins with ASCII plaintext or executable headers instead of `FF D8 FF`, a **`FILE SIGNATURE ANOMALY DETECTED (POTENTIAL SPOOFING)`** alert is raised.
2. **Chunked Dual Cryptographic Hashing (`app/services/hasher.py`):**
   * Reads files in **64 KB binary chunks** into Python's `hashlib` to compute both **MD5** (128-bit) and **SHA-256** (256-bit).
   * *Why chunked?* Prevents Out-Of-Memory (OOM) crashes when examining multi-gigabyte files or disk dumps.
3. **Deep Metadata Extraction (`app/services/metadata_extractor.py`):**
   * **Images (Pillow):** Dimensions, color mode, EXIF camera tags (Make, Model, Software, Timestamps), and GPS coordinates decoded into decimal latitude/longitude with direct Google Maps links.
   * **PDF Documents (pypdf):** Page counts, encryption state, and catalog metadata (Author, Producer, Creator).
   * **Plaintext / System Logs:** Character encoding (UTF-8, ASCII), line/word/character statistics, and newline conventions (`CRLF` vs `LF`).
   * **Host Timestamps:** Captures operating system creation, modification, and access timestamps.

### Step 3: AI Threat Triage & Blockchain Ledger
* The **AI Forensic Engine** evaluates anomalies, calculates a **Risk Score (0–100)**, assigns a threat tier (`LOW`, `ELEVATED`, `SUSPICIOUS`, `CRITICAL`), and generates natural language recommendations.
* The **Blockchain Engine** mines an immutable block sealing the evidence ID and SHA-256 hash with Proof-of-Work, linking to the previous block's hash.

### Step 4: Verification & Court-Ready Export
* **File Integrity Verification (`/integrity`):** Compares live candidate files against baseline hashes.
* **Blockchain Verification (`/blockchain`):** Cryptographically audits the entire custody chain for tampering.
* **ReportLab PDF Export (`/reports/<id>/download`):** Compiles an official examination docket.

---

## 3. The Blockchain Concept Explained (How It Works Under the Hood)

### The Anatomy of a Block (`app/services/blockchain.py`)
Each block in our forensic chain contains 8 evidentiary fields:

```json
{
  "index_num": 1,
  "timestamp": "2026-11-17 11:30:00 UTC",
  "evidence_id": "EVD-20261117-98A1B2C3",
  "case_number": "CASE-2026-ALPHA",
  "file_hash": "a1b2c3d4... (SHA-256 baseline of the evidence)",
  "previous_hash": "0000a4b7... (The cryptographic seal of Block #0)",
  "nonce": 4218,
  "block_hash": "009f4b32... (The cryptographic seal of THIS block)"
}
```

### Cryptographic Chaining Formula
Every block's signature (`block_hash`) is computed from its own data **plus the previous block's hash**:

$$\text{Block Hash} = \text{SHA-256}(\text{Index} + \text{Timestamp} + \text{Evidence ID} + \text{Case Number} + \text{File Hash} + \mathbf{Previous\ Hash} + \text{Nonce})$$

```
+-----------------------------------+       +-----------------------------------+       +-----------------------------------+
|             BLOCK #0              |       |             BLOCK #1              |       |             BLOCK #2              |
|  Evidence: GENESIS-ROOT           |       |  Evidence: EVD-001 (document.pdf) |       |  Evidence: EVD-002 (log.txt)      |
|  Prev Hash: 0000000000000000...   |       |  Prev Hash: 004f8a9b2c...         |       |  Prev Hash: 009e7c1d3a...         |
|  Block Hash: 004f8a9b2c...        | <---+ |  Block Hash: 009e7c1d3a...        | <---+ |  Block Hash: 002a5b8f4e...        |
+-----------------------------------+       +-----------------------------------+       +-----------------------------------+
```

### Proof-of-Work (PoW) Consensus
* The code enforces a mining difficulty target (`DIFFICULTY = 2`), requiring every valid block hash to start with **`"00"`**.
* The miner increments the `nonce` until the SHA-256 hash satisfies the prefix `"00"`.
* *Why PoW is essential:* It introduces computational cost, making it mathematically impossible for a rogue attacker to silently rewrite historical blocks without re-mining the entire chain.

### The Tamper-Evident Mechanism (The Avalanche Effect)
If someone modifies even a single character of `file_hash` in Block #1:
1. Re-hashing Block #1 produces a completely different hash that **no longer begins with `"00"`**.
2. Block #1's hash no longer matches the recorded `block_hash`.
3. Block #2's `previous_hash` still references the *old* hash of Block #1, breaking the chain link.
4. When clicking **⚡ Verify Blockchain Integrity**, the system detects this mismatch and triggers:
   > **`🚨 CRITICAL INTEGRITY BREACH at Block #1: Computed hash does not match recorded block hash. Data has been tampered with!`**

---

## 4. AI Forensic Threat Analysis Engine

Implemented in `app/services/ai_analyzer.py`, this module evaluates multiple risk dimensions:

1. **Extension Masquerading / Header Spoofing:** Flags discrepancies between declared file extension and binary magic numbers (adds +65 risk points).
2. **Metadata Tampering & Anti-Forensics:** Scans EXIF tags for editing utilities (`Photoshop`, `GIMP`, `ExifTool`, `HxD`) and detects high-value GPS coordinates.
3. **Document Exploitation Tools:** Scans PDF Producer/Creator catalogs for exploitation utilities (`Metasploit`, `Kali scripts`).
4. **Malicious Plaintext Payloads:** Scans log previews for injection patterns (`powershell`, `cmd.exe`, `eval(`, `base64`, `DROP TABLE`, `UNION SELECT`).
5. **Dynamic Threat Classification:**
   * `0 - 24`: **LOW / SAFE** (Clean, standard evidentiary artifact)
   * `25 - 49`: **ELEVATED MONITORING** (Minor header or timestamp anomalies)
   * `50 - 74`: **SUSPICIOUS ARTIFACT** (Tooling artifacts or irregular parameters)
   * `75 - 100`: **CRITICAL FORENSIC THREAT** (Confirmed extension spoofing or attack payloads)
6. **Automated Findings & Recommendations:** Generates an executive summary and actionable investigator instructions (e.g. sandbox detonation, hex dump analysis, cell-tower timeline correlation).

---

## 5. Automated Forensic Report Generation (ReportLab PDF)

Unlike web dashboards which are interactive and ephemeral, legal investigations require a **portable, immutable, court-admissible document**. Built programmatically with **ReportLab** (`app/services/report_generator.py`):

* **Section 1: Case & Chain of Custody:** Case Number, Lead Examiner name, Ingestion timestamp, and Vault reference.
* **Section 2: Evidence Item Specifications & Signature Analysis:** Original filename, exact file size in bytes, declared vs. detected MIME types, and Magic Byte verification status.
* **Section 3: Cryptographic Integrity Baseline:** Baseline **MD5** and **SHA-256** digests in monospaced font.
* **Section 4: Blockchain Proof of Custody Seal:** Block index, Proof-of-Work Block Hash, Previous Block Hash, Nonce, and Mining timestamp.
* **Section 5: AI Forensic Threat Assessment:** AI Threat Classification, Calculated Risk Score, Executive Summary, and Recommended Investigative Actions.
* **Section 6: Extracted Metadata & Forensic Artifacts:** EXIF tags, GPS links, PDF catalog properties, and host OS timestamps.
* **Section 7: Forensic Limitations & Disclaimers:** Evidentiary limitation clauses.
* **Section 8: Examiner Sign-off:** Signature line and laboratory verification seal.

---

## 6. Forensic Evidentiary Disclaimers & Legal Caveats

The application explicitly embeds core forensic principles into both the UI and PDF reports:
* **Baseline Integrity vs. Pre-Seizure Authenticity:** A matching SHA-256 cryptographic digest or valid blockchain block proves that the file has remained bitstream-identical *since intake into this system*. It does **not** certify that the evidence was authentic, unmodified, or legitimate prior to acquisition.
* **Timestamp & Metadata Volatility:** Timestamps, EXIF headers, and document attributes are subject to manipulation, anti-forensics, and clock skews. They represent investigative leads, not absolute mathematical proof of origination.

---

## 7. Technology Stack

* **Backend Framework:** Python 3.12, Flask 3.1 (Application Factory, Blueprints)
* **Cryptographic & Hash Engine:** Python `hashlib` (MD5, SHA-256, Proof-of-Work Block Hashing)
* **Metadata Extraction:** `Pillow` (Image EXIF/GPS decoding), `pypdf` (PDF catalog properties)
* **Database & Ledger:** SQLite 3 (Evidence records, verification audit logs, blockchain blocks)
* **Report Generation:** `ReportLab` (Platypus Flowable Architecture)
* **Frontend:** Responsive HTML5, Vanilla JavaScript, CSS3 Light Theme, Google Fonts (*Plus Jakarta Sans* & *JetBrains Mono*), Chart.js

---

## 8. Project Architecture & Directory Structure

```text
Cyber security/
├── app/
│   ├── __init__.py                # Flask app factory, config & DB initialization
│   ├── config.py                  # Storage paths, upload constraints, secret keys
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
├── sample_evidence/               # Generated test evidence samples
│   ├── sample_document.pdf        # Clean forensic document
│   ├── sample_image.png           # Clean digital image
│   ├── sample_log.txt             # Clean system auth log
│   └── spoofed_image.jpg          # Plaintext payload disguised as JPEG
├── tests/
│   └── test_suite.py              # 8 automated unit & integration tests
├── create_samples.py              # Sample generator script
├── tamper_blockchain.py           # Demonstration: Simulates database tampering
├── repair_blockchain.py           # Demonstration: Restores tampered block
├── restore_blockchain.py          # Demonstration: Resets chain to Genesis root
├── requirements.txt               # Python package dependencies
├── run.py                         # Application execution entrypoint
└── README.md                      # Comprehensive project documentation
```

---

## 9. Installation & Setup

### 1. Prerequisites
Ensure **Python 3.10+** is installed on your computer.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Automated Tests
Execute the verification suite to test database initialization, blockchain PoW mining, tamper detection, AI threat scoring, hashing consistency, spoof detection, and PDF generation:
```bash
python -m unittest tests/test_suite.py
```
*(All 8 unit & integration tests pass with 100% success).*

### 4. Start the Application
```bash
python run.py
```
Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## 10. Testing & Live Demonstration Guide

### Demo 1: Evidence Ingestion & AI Triage
1. Open `http://127.0.0.1:5000/upload`.
2. Upload `sample_evidence/sample_document.pdf`.
3. Provide Case ID (`CASE-2026-ALPHA`) and Examiner Name (`Analyst Smith`).
4. Click **Ingest & Perform Forensic Analysis**.
5. Observe:
   * **AI Assessment:** Classified as **LOW / SAFE** (Risk Score: 10/100).
   * **Blockchain Proof of Custody:** Anchored into **Block #1** with Proof-of-Work hash starting with `"00"`.
   * **Hashes:** Monospaced SHA-256 and MD5 baselines.

### Demo 2: Extension Spoofing Detection
1. Go to `/upload` and upload `sample_evidence/spoofed_image.jpg` (contains plaintext with a `.jpg` extension).
2. Click **Ingest & Perform Forensic Analysis**.
3. Observe:
   * **Signature Status:** Red alert **`⚠️ FILE SIGNATURE ANOMALY DETECTED (POTENTIAL SPOOFING)`**.
   * **AI Threat Assessment:** Classified as **CRITICAL FORENSIC THREAT** (Risk Score: 75/100), explaining payload concealment and recommending sandbox detonation.

### Demo 3: File Integrity Verification (Match vs. Tamper)
1. Go to `/integrity`.
2. **Match Test:** Select `sample_document.pdf` baseline and upload the identical file $\rightarrow$ **`✓ INTEGRITY VERIFIED: BITSTREAMS IDENTICAL`** (Green).
3. **Tamper Test:** Open `sample_evidence/sample_log.txt` in Notepad, modify one character, save as a copy, and upload $\rightarrow$ **`✕ INTEGRITY BREACH / HASH MISMATCH DETECTED`** (Red).

### Demo 4: The Blockchain Tampering Proof (The Ultimate Viva Demo)
*Show your examiner that the blockchain prevents rogue database tampering:*
1. Go to `http://127.0.0.1:5000/blockchain`.
2. Click **⚡ Verify Blockchain Integrity** $\rightarrow$ Status is **VALID (SECURE)**.
3. In your terminal, run:
   ```bash
   python tamper_blockchain.py
   ```
   *(This secretly alters the recorded hash of Block #1 in the database).*
4. In your browser, click **⚡ Verify Blockchain Integrity** again:
   * Status instantly turns **RED**:
   > **`🚨 CRITICAL INTEGRITY BREACH DETECTED at Block #1: Computed hash does not match recorded block hash. Data has been tampered with!`**
5. To repair the block during the demo:
   ```bash
   python repair_blockchain.py
   ```
   Click verify again $\rightarrow$ status turns back to **GREEN (VALID)**!

### Demo 5: PDF Forensic Report Download
1. On any evidence details page, click **📄 Download Forensic Report (PDF)**.
2. Open the downloaded PDF:
   * Features the **Blockchain Proof-of-Custody seal** (Block index, Block hash, Previous hash, Nonce).
   * Features the **AI Forensic Threat Assessment section** (Threat tier, Risk score, Executive findings, Recommendations).

---

## 11. College Viva & Presentation Q&A Preparation

| Expected Viva Question | Winning Answer to Give |
| :--- | :--- |
| **Q1: "Why do we need Blockchain if we already have SHA-256 hashing?"** | SHA-256 verifies the integrity of the *file*. But the recorded hash itself is stored in a database. If an insider administrator modifies the database, the baseline is corrupted. Blockchain seals the database records into cryptographically chained blocks, making it mathematically impossible to alter past baselines without invalidating the entire chain. |
| **Q2: "Does a matching SHA-256 hash prove that the evidence is authentic and genuine?"** | **No.** A matching hash proves **preservation integrity** (that the file hasn't changed since ingestion into this system). It cannot prove the file was authentic or unmanipulated *before* it was seized by investigators. (This legal disclaimer is explicitly embedded in our UI and PDF report). |
| **Q3: "Why do we generate both MD5 and SHA-256 hashes?"** | **MD5** (128-bit) is historically common for cross-referencing legacy threat intelligence databases, but is vulnerable to collision attacks. **SHA-256** (256-bit) is collision-resistant and accepted as the gold standard for court-admissible evidence. |
| **Q4: "Why check magic bytes instead of just the file extension?"** | File extensions (`.jpg`, `.pdf`) can be trivially renamed by anyone. Attackers rename malware or scripts to `.jpg` to evade email filters or trick victims. Checking **file header magic bytes** inspects the raw binary bytes (`FF D8 FF` for JPEG, `%PDF-` for PDF) to verify what the file *actually* is. |
| **Q5: "Why use chunked binary reading (`64 KB`) instead of `f.read()`?"** | Digital evidence files can be gigabytes in size (e.g. disk images or CCTV footage). Loading entire files into RAM at once causes Out-Of-Memory (OOM) crashes. Streaming in 64 KB chunks keeps RAM consumption negligible regardless of file size. |
| **Q6: "What is Proof-of-Work (PoW) doing in this project?"** | PoW enforces a mathematical puzzle (hash must start with `"00"`). It forces the system to find a valid `nonce` before creating a block. This ensures that an attacker cannot rewrite historical blocks in milliseconds; they would have to re-mine every subsequent block on the chain. |

---

## License & Attribution
Developed as an academic mini-project in Digital Forensics & Cybersecurity. Open-source under the MIT License.
