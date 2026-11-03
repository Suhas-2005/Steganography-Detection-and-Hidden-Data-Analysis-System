"""
StegAnalyzer – Sample Test Data Generator.

Generates realistic forensic test samples matching all project testing criteria:
  • Sample 1: Normal JPEG image (TEST 1)
  • Sample 2: Normal BMP image (TEST 2 carrier)
  • Sample 3: PNG image (TEST 5 - Steghide unsupported format test)
  • Sample 4: JPEG with appended ZIP archive (TEST 4 - Binwalk / trailing data test)
  • Sample 5: Plain text disguised as JPEG (TEST 6 - File validation failure test)
"""

import io
import zipfile
from pathlib import Path
from PIL import Image, ImageDraw

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
SAMPLES_DIR.mkdir(exist_ok=True)


def create_normal_jpeg():
    path = SAMPLES_DIR / "sample1_normal.jpg"
    img = Image.new("RGB", (320, 240), color="#1e3a8a")
    draw = ImageDraw.Draw(img)
    draw.text((20, 100), "StegAnalyzer Forensic Sample 1 (Clean)", fill="#f8fafc")
    img.save(path, "JPEG", quality=95)
    print(f"[+] Created clean JPEG: {path}")
    return path


def create_normal_bmp():
    path = SAMPLES_DIR / "sample2_normal.bmp"
    img = Image.new("RGB", (200, 200), color="#059669")
    draw = ImageDraw.Draw(img)
    draw.text((20, 90), "BMP Steg Carrier", fill="#ffffff")
    img.save(path, "BMP")
    print(f"[+] Created clean BMP: {path}")
    return path


def create_normal_png():
    path = SAMPLES_DIR / "sample3_format_test.png"
    img = Image.new("RGBA", (250, 150), color=(14, 165, 233, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 60), "PNG Carrier (Unsupported for Steghide)", fill=(255, 255, 255, 255))
    img.save(path, "PNG")
    print(f"[+] Created PNG image: {path}")
    return path


def create_appended_zip_jpeg():
    # Concatenating a valid zip archive after the JPEG EOI (End of Image) marker
    path = SAMPLES_DIR / "sample4_appended_archive.jpg"
    base_img = Image.new("RGB", (320, 240), color="#7c3aed")
    draw = ImageDraw.Draw(base_img)
    draw.text((20, 100), "JPEG with Appended Secret Archive", fill="#ffffff")

    buf = io.BytesIO()
    base_img.save(buf, "JPEG")
    jpeg_bytes = buf.getvalue()

    # Create in-memory ZIP payload
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("confidential_memo.txt", "CASE #90214: Evidence of unauthorized data transfer.\nStatus: CLASSIFIED.")
    zip_bytes = zip_buf.getvalue()

    # Concatenate JPEG + ZIP
    combined = jpeg_bytes + zip_bytes
    path.write_bytes(combined)
    print(f"[+] Created JPEG with trailing ZIP archive: {path}")
    return path


def create_invalid_fake_jpeg():
    path = SAMPLES_DIR / "sample5_invalid_spoofed.jpg"
    content = b"Not a JPEG image! This is ASCII text renamed with a .jpg extension to test forensic validation rejection."
    path.write_bytes(content)
    print(f"[+] Created spoofed invalid image: {path}")
    return path


def main():
    print("Generating forensic test samples in:", SAMPLES_DIR)
    create_normal_jpeg()
    create_normal_bmp()
    create_normal_png()
    create_appended_zip_jpeg()
    create_invalid_fake_jpeg()
    print("All samples successfully generated.")


if __name__ == "__main__":
    main()

