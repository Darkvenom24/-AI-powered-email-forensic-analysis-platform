"""
Automated Test Suite for Dynamic File Validation and Security Hardening
========================================================================
Tests:
1. Legitimate .eml files are accepted.
2. Direct .exe files are blocked.
3. Renamed/Disguised .exe files with .eml extension (MZ magic bytes) are blocked.
4. Other dangerous extensions (.dll, .bat, .cmd, .sh, .bin, .msi, .scr, etc.) are blocked.
5. Archives (.zip, .jar) and PDFs are blocked.
6. Empty files (0 bytes) are blocked.
7. Double-extension disguise attacks (e.g. malware.exe.eml) are blocked.
8. Binary null bytes in text are blocked.
9. Flask integration: /api/analyze returns 400 on invalid files and 200 on valid .eml.
10. Flask integration: Web UI POST rejects invalid files gracefully.
11. process_email_source raises ValueError on executable bytes.
"""

import io
import unittest
from app import app, process_email_source
from src.file_validator import (
    validate_email_upload,
    validate_email_text_payload,
    MAX_EMAIL_FILE_SIZE
)

class TestFileSecurityValidation(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Valid RFC 822 email bytes
        with open("data/test_email.eml", "rb") as f:
            self.valid_eml_bytes = f.read()

        # Simulated Windows Executable (PE / DOS header MZ)
        self.exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 200

        # Simulated Linux ELF executable
        self.elf_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200

        # Simulated ZIP archive
        self.zip_bytes = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 100

        # Simulated PDF document
        self.pdf_bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"some pdf content" * 10

    def test_01_valid_eml_accepted(self):
        """Valid .eml file must be accepted."""
        is_valid, err, meta = validate_email_upload(self.valid_eml_bytes, "test_email.eml")
        self.assertTrue(is_valid, f"Valid .eml was rejected: {err}")
        self.assertIsNone(err)
        self.assertTrue(meta.get("is_valid"))

    def test_02_direct_exe_rejected(self):
        """Direct .exe file upload must be rejected with EXECUTABLE_FILE_BLOCKED."""
        is_valid, err, meta = validate_email_upload(self.exe_bytes, "payload.exe")
        self.assertFalse(is_valid)
        self.assertIn("executable", err.lower())
        self.assertEqual(meta.get("code"), "EXECUTABLE_FILE_BLOCKED")

    def test_03_disguised_exe_with_eml_ext_rejected(self):
        """An .exe renamed as .eml must be blocked by magic bytes inspection."""
        is_valid, err, meta = validate_email_upload(self.exe_bytes, "innocent.eml")
        self.assertFalse(is_valid)
        self.assertIn("executable", err.lower())
        self.assertIn(meta.get("code"), ["MALICIOUS_MAGIC_BYTES", "EXECUTABLE_MAGIC_BYTES"])

    def test_04_elf_binary_rejected(self):
        """Linux ELF binary renamed as .eml must be rejected."""
        is_valid, err, meta = validate_email_upload(self.elf_bytes, "linux_payload.eml")
        self.assertFalse(is_valid)
        self.assertIn("elf", err.lower())

    def test_05_zip_archive_rejected(self):
        """ZIP archives must be rejected."""
        is_valid, err, meta = validate_email_upload(self.zip_bytes, "archive.zip")
        self.assertFalse(is_valid)
        is_valid_renamed, err_renamed, meta_renamed = validate_email_upload(self.zip_bytes, "archive.eml")
        self.assertFalse(is_valid_renamed)
        self.assertIn("archive", err_renamed.lower())

    def test_06_pdf_document_rejected(self):
        """PDF documents must be rejected."""
        is_valid, err, _ = validate_email_upload(self.pdf_bytes, "invoice.pdf")
        self.assertFalse(is_valid)
        is_valid_renamed, err_renamed, _ = validate_email_upload(self.pdf_bytes, "invoice.eml")
        self.assertFalse(is_valid_renamed)
        self.assertIn("pdf", err_renamed.lower())

    def test_07_empty_file_rejected(self):
        """Empty 0-byte file must be rejected."""
        is_valid, err, _ = validate_email_upload(b"", "empty.eml")
        self.assertFalse(is_valid)
        self.assertIn("empty", err.lower())

    def test_08_double_extension_attack_rejected(self):
        """Files like invoice.exe.eml or drill.bat.eml must be rejected."""
        for dangerous_name in ["invoice.exe.eml", "script.bat.eml", "payload.scr.eml", "tool.dll.eml"]:
            is_valid, err, meta = validate_email_upload(self.valid_eml_bytes, dangerous_name)
            self.assertFalse(is_valid, f"Failed to reject double extension: {dangerous_name}")
            self.assertEqual(meta.get("code"), "DISGUISED_EXECUTABLE_BLOCKED")

    def test_09_other_dangerous_extensions_rejected(self):
        """Extensions like .dll, .bat, .cmd, .sh, .bin, .msi, .vbs must be blocked."""
        dangerous = ["test.dll", "test.bat", "test.cmd", "test.sh", "test.bin", "test.msi", "test.vbs"]
        for fn in dangerous:
            is_valid, err, _ = validate_email_upload(b"some bytes", fn)
            self.assertFalse(is_valid, f"Failed to reject dangerous extension: {fn}")

    def test_10_text_validation_with_null_bytes(self):
        """Text payload containing binary null bytes must be rejected."""
        is_valid, err, meta = validate_email_text_payload("From: test@test.com\x00\x00binary")
        self.assertFalse(is_valid)
        self.assertEqual(meta.get("code"), "BINARY_TEXT_DETECTED")

    def test_11_api_analyze_rejects_exe(self):
        """POST /api/analyze with .exe must return 400 Bad Request."""
        data = {
            "email_file": (io.BytesIO(self.exe_bytes), "test_program.exe")
        }
        response = self.app.post("/api/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        res_json = response.get_json()
        self.assertFalse(res_json["success"])
        self.assertIn("executable", res_json["error"].lower())

    def test_12_api_analyze_rejects_disguised_exe(self):
        """POST /api/analyze with disguised .exe renamed as .eml must return 400 Bad Request."""
        data = {
            "email_file": (io.BytesIO(self.exe_bytes), "malware.eml")
        }
        response = self.app.post("/api/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        res_json = response.get_json()
        self.assertFalse(res_json["success"])
        self.assertIn("executable", res_json["error"].lower())

    def test_13_api_analyze_accepts_valid_eml(self):
        """POST /api/analyze with valid .eml file must succeed (200 OK)."""
        data = {
            "email_file": (io.BytesIO(self.valid_eml_bytes), "test_email.eml")
        }
        response = self.app.post("/api/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        res_json = response.get_json()
        self.assertTrue(res_json["success"])
        self.assertIn("risk_score", res_json["data"])

    def test_14_process_email_source_safety_guard(self):
        """process_email_source must raise ValueError if called directly with .exe bytes."""
        with self.assertRaises(ValueError) as ctx:
            process_email_source(raw_bytes=self.exe_bytes)
        self.assertIn("executable", str(ctx.exception).lower())

    def test_15_web_ui_rejects_exe(self):
        """POST / with .exe must return rendered template with error message."""
        data = {
            "email_file": (io.BytesIO(self.exe_bytes), "installer.exe")
        }
        response = self.app.post("/", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("executable", html.lower())

    def test_16_aadhaar_pdf_rejected(self):
        """Upload of an Aadhaar PDF document must return 400 DOCUMENT_FILE_REJECTED."""
        data = {
            "email_file": (io.BytesIO(self.pdf_bytes), "eaadhaar.pdf")
        }
        response = self.app.post("/api/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertEqual(res["code"], "DOCUMENT_FILE_REJECTED")

    def test_17_aadhaar_photo_rejected(self):
        """Upload of an Aadhaar card photo/image must return 400 IMAGE_FILE_REJECTED."""
        jpg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"image_data" * 20
        data = {
            "email_file": (io.BytesIO(jpg_bytes), "my_aadhaar_card.jpg")
        }
        response = self.app.post("/api/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertEqual(res["code"], "IMAGE_FILE_REJECTED")

    def test_18_disguised_aadhaar_rejected(self):
        """Disguised Aadhaar card text renamed to .eml must be rejected as IDENTITY_DOCUMENT_REJECTED."""
        aadhaar_eml = (
            b"GOVERNMENT OF INDIA\n"
            b"Unique Identification Authority of India\n"
            b"Aadhaar No: 1234 5678 9012\n"
            b"Name: Test User\n"
            b"Email: help@uidai.gov.in\n"
        )
        data = {
            "email_file": (io.BytesIO(aadhaar_eml), "aadhaar.eml")
        }
        response = self.app.post("/api/analyze", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertEqual(res["code"], "IDENTITY_DOCUMENT_REJECTED")

    def test_19_aadhaar_text_payload_rejected(self):
        """Pasted Aadhaar card text payload must be rejected as IDENTITY_DOCUMENT_REJECTED."""
        payload = {
            "email_text": (
                "GOVERNMENT OF INDIA\n"
                "Unique Identification Authority of India\n"
                "Aadhaar Number: 9876 5432 1098\n"
                "Name: Ramesh Kumar\n"
                "DOB: 12/05/1992\n"
                "help@uidai.gov.in"
            )
        }
        response = self.app.post("/api/analyze", json=payload)
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertEqual(res["code"], "IDENTITY_DOCUMENT_REJECTED")

    def test_20_pan_card_rejected(self):
        """PAN Card document/text must be rejected as IDENTITY_DOCUMENT_REJECTED."""
        pan_payload = {
            "email_text": (
                "INCOME TAX DEPARTMENT\n"
                "GOVT. OF INDIA\n"
                "Permanent Account Number Card\n"
                "PAN: ABCDE1234F\n"
                "Name: Suresh Patel\n"
            )
        }
        response = self.app.post("/api/analyze", json=pan_payload)
        self.assertEqual(response.status_code, 400)
        res = response.get_json()
        self.assertFalse(res["success"])
        self.assertEqual(res["code"], "IDENTITY_DOCUMENT_REJECTED")

if __name__ == "__main__":
    unittest.main(verbosity=2)
