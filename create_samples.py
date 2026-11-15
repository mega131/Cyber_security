"""
Sample Evidence Generator for Digital Forensic Evidence Analyzer
Generates test files to verify all features:
1. sample_image.png (Genuine Image)
2. sample_document.pdf (Genuine PDF Document)
3. sample_log.txt (Genuine System Log)
4. spoofed_image.jpg (Spoofed File: Text file disguised as JPEG to test magic byte anomaly detection)
"""
from pathlib import Path
from PIL import Image, ImageDraw
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def create_sample_files():
    sample_dir = Path("sample_evidence")
    sample_dir.mkdir(exist_ok=True)

    # 1. Genuine Image (PNG)
    img_path = sample_dir / "sample_image.png"
    img = Image.new('RGB', (400, 200), color=(15, 23, 42))
    d = ImageDraw.Draw(img)
    d.text((30, 80), "DIGITAL FORENSIC EVIDENCE SAMPLE", fill=(0, 229, 255))
    img.save(img_path, format="PNG")
    print(f"[+] Created: {img_path}")

    # 2. Genuine PDF Document
    pdf_path = sample_dir / "sample_document.pdf"
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    c.setTitle("Forensic Case Investigation Docket")
    c.setAuthor("Investigator Smith")
    c.drawString(100, 700, "CONFIDENTIAL INVESTIGATION SUMMARY")
    c.drawString(100, 670, "Case ID: CASE-2026-ALPHA")
    c.drawString(100, 640, "Subject: Unauthorized Data Exfiltration Suspect Log")
    c.save()
    print(f"[+] Created: {pdf_path}")

    # 3. Genuine Text/Log File
    log_path = sample_dir / "sample_log.txt"
    log_content = (
        "2026-11-14 20:15:01 [AUTH] User 'admin' logged in from 192.168.1.45\n"
        "2026-11-14 20:18:22 [FILE] Download request for /vault/classified_dataset.db\n"
        "2026-11-14 20:19:10 [ALERT] USB Mass Storage device connected (VID:0781, PID:5583)\n"
        "2026-11-14 20:20:00 [SYSTEM] Forensic snapshot initiated.\n"
    )
    log_path.write_text(log_content, encoding="utf-8")
    print(f"[+] Created: {log_path}")

    # 4. Spoofed File (Text content saved with .jpg extension)
    spoof_path = sample_dir / "spoofed_image.jpg"
    spoofed_content = (
        "MZ-EXE-HEADER-SIMULATION\n"
        "This is an executable payload disguised with a .jpg extension to bypass filters.\n"
    )
    spoof_path.write_bytes(spoofed_content.encode("utf-8"))
    print(f"[+] Created: {spoof_path} (Spoofed extension test)")

    print(f"\nAll 4 test evidence files generated in: {sample_dir.resolve()}")

if __name__ == '__main__':
    create_sample_files()
