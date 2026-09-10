"""
SIH26106: Email Forensic Ingestion & File Security Validator
============================================================
Strict multi-layer validation engine for uploaded files and raw text payloads.
Enforces that ONLY valid RFC 822 / MIME (.eml) email files are ingested,
blocking executables (.exe, .dll, .elf, etc.), scripts, archives, and non-email formats.
"""

import os
import re
from typing import Tuple, Dict, Any, Optional

# Maximum allowed file size for email analysis (default: 15 MB)
MAX_EMAIL_FILE_SIZE = 15 * 1024 * 1024

# Strictly allowed extension
ALLOWED_EXTENSIONS = {".eml"}

# Dangerous executable / script extensions strictly forbidden anywhere in filename
DANGEROUS_EXTENSIONS = {
    "exe", "dll", "sys", "com", "scr", "pif", "bat", "cmd", "ps1", "vbs",
    "vbe", "js", "jse", "wsf", "wsh", "msc", "msi", "msp", "reg", "hta",
    "jar", "app", "dmg", "pkg", "deb", "rpm", "elf", "bin", "so", "dylib",
    "sh", "bash", "csh", "py", "pl", "php"
}

# Known binary magic byte signatures that must be rejected
MAGIC_SIGNATURES = [
    # DOS / Windows PE Executable (EXE, DLL, OCX, SYS, SCR)
    (b"MZ", "Executable file (.exe / PE binary) detected. Windows executables cannot be analyzed as emails."),
    # Linux / Unix ELF Binary
    (b"\x7fELF", "Linux ELF executable binary detected. Executables cannot be analyzed as emails."),
    # Mach-O Executables (macOS)
    (b"\xfe\xed\xfa\xce", "macOS Mach-O 32-bit executable detected."),
    (b"\xfe\xed\xfa\xcf", "macOS Mach-O 64-bit executable detected."),
    (b"\xce\xfa\xed\xfe", "macOS Mach-O executable detected (reverse endian)."),
    (b"\xcf\xfa\xed\xfe", "macOS Mach-O executable detected (reverse endian)."),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O Universal binary detected."),
    # ZIP / JAR / APK archives
    (b"PK\x03\x04", "Archive file (.zip / .jar) detected. Archives must be extracted; only individual .eml files are permitted."),
    (b"PK\x05\x06", "Empty ZIP archive detected."),
    # RAR Archives
    (b"Rar!\x1a\x07", "RAR archive detected. Archives must be extracted; only individual .eml files are permitted."),
    # 7-Zip Archives
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive detected. Archives must be extracted; only individual .eml files are permitted."),
    # PDF Documents
    (b"%PDF-", "PDF document detected. PDF files cannot be analyzed directly as raw .eml emails."),
    # Standard Media Files
    (b"\xff\xd8\xff", "JPEG image binary detected."),
    (b"\x89PNG\r\n\x1a\n", "PNG image binary detected."),
    (b"GIF87a", "GIF image binary detected."),
    (b"GIF89a", "GIF image binary detected."),
]

# Regex pattern for RFC 5322 / MIME email headers
EMAIL_HEADER_PATTERN = re.compile(
    r"(?im)^(?:From|To|Subject|Date|Received|Message-ID|Return-Path|MIME-Version|"
    r"Content-Type|Delivered-To|DKIM-Signature|Authentication-Results|X-[a-zA-Z0-9_-]+)\s*:"
)


def validate_email_upload(
    file_obj_or_bytes: Any,
    filename: Optional[str] = None
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Perform multi-layer security & format validation on an uploaded email file.

    Checks performed:
    1. Empty file check
    2. File size limit enforcement
    3. Filename & extension analysis (must end in .eml, no dangerous double-extensions)
    4. Binary magic-byte inspection (blocking .exe MZ headers, ELF, Mach-O, archives, etc.)
    5. Null-byte density inspection (ensuring content is text, not binary)
    6. RFC 822 / MIME email structure verification (detecting valid email headers)

    Returns:
        (is_valid: bool, error_message: Optional[str], metadata: dict)
    """
    raw_bytes: bytes = b""
    fname: str = ""

    # Extract filename and bytes from either FileStorage or raw bytes
    if hasattr(file_obj_or_bytes, "read") and hasattr(file_obj_or_bytes, "filename"):
        fname = (filename or file_obj_or_bytes.filename or "").strip()
        try:
            file_obj_or_bytes.seek(0)
            raw_bytes = file_obj_or_bytes.read()
            # Reset seek position for subsequent consumption
            file_obj_or_bytes.seek(0)
        except Exception as e:
            return False, f"Failed to read uploaded file: {str(e)}", {"code": "READ_ERROR"}
    elif isinstance(file_obj_or_bytes, (bytes, bytearray)):
        raw_bytes = bytes(file_obj_or_bytes)
        fname = (filename or "uploaded_file.eml").strip()
    else:
        return False, "Invalid file object provided.", {"code": "INVALID_OBJECT"}

    file_size = len(raw_bytes)
    details: Dict[str, Any] = {
        "filename": fname,
        "size_bytes": file_size,
        "extension": os.path.splitext(fname)[1].lower() if fname else ""
    }

    # 1. Check filename presence
    if not fname:
        return False, "No filename provided. Please upload a valid .eml file.", details

    # 2. Check empty file
    if file_size == 0 or not raw_bytes.strip():
        return False, "The uploaded file is empty (0 bytes). Please upload a valid .eml email file.", details

    # 3. Check file size limit
    if file_size > MAX_EMAIL_FILE_SIZE:
        max_mb = MAX_EMAIL_FILE_SIZE // (1024 * 1024)
        return False, f"Uploaded file exceeds maximum limit of {max_mb} MB ({file_size / (1024*1024):.1f} MB uploaded).", details

    # 4. Strict Filename & Extension Verification
    clean_fname = os.path.basename(fname).strip()
    name_lower = clean_fname.lower()
    _, ext = os.path.splitext(name_lower)

    if ext not in ALLOWED_EXTENSIONS:
        if ext in [f".{d}" for d in DANGEROUS_EXTENSIONS]:
            return (
                False,
                f"Security Violation: '{clean_fname}' is an executable or dangerous file type ({ext}). "
                f"Only RFC 822 email files (.eml) are permitted for forensic analysis.",
                {**details, "code": "EXECUTABLE_FILE_BLOCKED", "blocked_ext": ext}
            )
        return (
            False,
            f"Unsupported file format '{ext or 'unknown'}'. "
            f"Only RFC 822 email files (.eml) are supported for forensic investigation.",
            {**details, "code": "INVALID_EXTENSION", "allowed": [".eml"]}
        )

    # 5. Multi-Extension & Double Extension Defense (e.g., payload.exe.eml)
    tokens = [t.lower() for t in clean_fname.split(".")]
    if len(tokens) > 2:
        inner_extensions = set(tokens[1:-1])
        conflicting = inner_extensions.intersection(DANGEROUS_EXTENSIONS)
        if conflicting:
            conf_ext = list(conflicting)[0]
            return (
                False,
                f"Security Violation: Double extension detected with dangerous payload signature (.{conf_ext}). "
                f"Disguised executable files are strictly prohibited.",
                {**details, "code": "DISGUISED_EXECUTABLE_BLOCKED", "dangerous_inner_ext": conf_ext}
            )

    # 6. Binary Magic Byte Signature Inspection
    header_chunk_512 = raw_bytes[:512]
    for signature, error_desc in MAGIC_SIGNATURES:
        if header_chunk_512.startswith(signature):
            return (
                False,
                f"Security Rejection: {error_desc}",
                {**details, "code": "MALICIOUS_MAGIC_BYTES", "signature": signature.hex()}
            )

    # Additional executable search: If MZ is within first 16 bytes (some packed PE headers)
    if b"MZ" in header_chunk_512[:16]:
        return (
            False,
            "Security Rejection: Executable binary signature (MZ / PE) detected. Executables cannot be analyzed as emails.",
            {**details, "code": "EXECUTABLE_MAGIC_BYTES"}
        )

    # 7. Null-Byte Density Check
    # Valid EML files are ASCII / UTF-8 text with headers. Binary files contain dense null bytes (\x00).
    sample_chunk = raw_bytes[:min(4096, file_size)]
    null_count = sample_chunk.count(b"\x00")
    if len(sample_chunk) > 0 and (null_count / len(sample_chunk)) > 0.01:
        return (
            False,
            "Binary File Rejected: The uploaded file contains binary byte sequences and is not a valid text-based email.",
            {**details, "code": "BINARY_FILE_REJECTED", "null_byte_ratio": null_count / len(sample_chunk)}
        )

    # 8. RFC 822 / MIME Email Header Structure Verification
    # An EML file MUST start with standard email headers or MIME markers.
    try:
        header_text = sample_chunk.decode("utf-8", errors="replace")
    except Exception:
        header_text = sample_chunk.decode("latin-1", errors="replace")

    headers_found = EMAIL_HEADER_PATTERN.findall(header_text)
    if not headers_found:
        # Check if entire content is at least plain text with some email cues
        has_at_symbol = "@" in header_text
        has_message_body = len(header_text.strip()) > 15
        if not (has_at_symbol and has_message_body):
            return (
                False,
                "Invalid Email Structure: The uploaded file does not contain valid RFC 822 email headers "
                "(e.g., From, To, Subject, Date, Received) or recognizable email content.",
                {**details, "code": "INVALID_EMAIL_HEADERS"}
            )

    details["headers_found_sample"] = headers_found[:5]
    details["is_valid"] = True
    return True, None, details


def validate_email_text_payload(text_content: Optional[str]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Validate raw pasted email text content from textarea or JSON payload.
    Ensures it is non-empty, contains readable text, and is not binary data.
    """
    if not text_content or not isinstance(text_content, str):
        return False, "No email text provided.", {"code": "EMPTY_TEXT"}

    clean_text = text_content.strip()
    if not clean_text:
        return False, "Email text content cannot be blank.", {"code": "BLANK_TEXT"}

    if len(clean_text) < 15:
        return False, "Email text is too short to be an email message (minimum 15 characters required).", {"code": "TEXT_TOO_SHORT"}

    # Check for null bytes or binary characters
    if "\x00" in clean_text:
        return False, "Binary data detected in text input. Executables and binary files cannot be pasted.", {"code": "BINARY_TEXT_DETECTED"}

    return True, None, {"length": len(clean_text), "is_valid": True}
