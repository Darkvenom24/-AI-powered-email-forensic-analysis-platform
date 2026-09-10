"""
SIH26106: Email Forensic Ingestion & File Security Validator
============================================================
Strict multi-layer validation engine for uploaded files and raw text payloads.
Enforces that ONLY valid RFC 822 / MIME (.eml) email files are ingested,
blocking executables (.exe, .dll, .elf, etc.), scripts, archives,
identity documents (Aadhaar cards, PAN cards), and non-email formats (PDFs, images).
"""

import os
import re
from typing import Tuple, Dict, Any, Optional

# Maximum allowed file size for email analysis (default: 15 MB)
MAX_EMAIL_FILE_SIZE = 15 * 1024 * 1024

# Strictly allowed extension
ALLOWED_EXTENSIONS = {".eml"}

# Image extensions (common Aadhaar card photos, screenshots, etc.)
IMAGE_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tiff", "tif",
    "svg", "ico", "heic", "jfif", "avif"
}

# Document & spreadsheet extensions (common e-Aadhaar PDFs, office documents)
DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "odt", "ods", "odp", "rtf", "xml", "csv", "tsv"
}

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
    # PDF Documents (e.g. e-Aadhaar card PDF)
    (b"%PDF-", "PDF document detected. Aadhaar card PDFs and document files cannot be analyzed directly as raw .eml emails."),
    # Standard Media Files (e.g. Aadhaar card photos / scans)
    (b"\xff\xd8\xff", "JPEG image binary detected. Aadhaar photos and image files cannot be analyzed as emails."),
    (b"\x89PNG\r\n\x1a\n", "PNG image binary detected. Scanned cards and image files cannot be analyzed as emails."),
    (b"GIF87a", "GIF image binary detected."),
    (b"GIF89a", "GIF image binary detected."),
    (b"BM", "Windows Bitmap (BMP) image detected."),
    (b"II*\x00", "TIFF image detected."),
    (b"MM\x00*", "TIFF image detected."),
    # Microsoft Office Compound File (OLE)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Microsoft Office binary document (DOC/XLS/PPT) detected."),
]

# Regex pattern for RFC 5322 / MIME email headers
EMAIL_HEADER_PATTERN = re.compile(
    r"(?im)^(?:From|To|Subject|Date|Received|Message-ID|Return-Path|MIME-Version|"
    r"Content-Type|Delivered-To|DKIM-Signature|Authentication-Results|X-[a-zA-Z0-9_-]+)\s*:"
)


def check_identity_document(text: str) -> Optional[Tuple[str, str]]:
    """
    Detect if text belongs to an Aadhaar card, PAN card, or Indian identity record
    rather than an email message.
    """
    text_lower = text.lower()

    # 1. Aadhaar Card detection
    aadhaar_keywords = [
        "aadhaar", "uidai", "mera aadhaar", "unique identification authority",
        "enrollment no", "enrolment no", "vid :"
    ]
    has_aadhaar_keyword = any(k in text_lower for k in aadhaar_keywords)
    has_aadhaar_number = bool(re.search(r"\b\d{4}\s\d{4}\s\d{4}\b", text))
    has_uidai_email = "help@uidai.gov.in" in text_lower

    if has_aadhaar_keyword or has_uidai_email or (has_aadhaar_number and "government of india" in text_lower):
        return (
            "Aadhaar Card",
            "Indian Aadhaar Card / UIDAI identity document detected. Personal identity documents cannot be ingested for email forensic analysis."
        )

    # 2. PAN Card detection
    pan_keywords = ["income tax department", "permanent account number", "govt. of india pan"]
    has_pan_keyword = any(k in text_lower for k in pan_keywords)
    has_pan_number = bool(re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", text))
    if has_pan_keyword or (has_pan_number and ("income tax" in text_lower or "father's name" in text_lower)):
        return (
            "PAN Card",
            "Income Tax PAN Card detected. Identity documents cannot be analyzed as email files."
        )

    # 3. Passport / Driving License / Voter ID
    if "republic of india" in text_lower and "passport" in text_lower:
        return ("Passport", "Indian Passport document detected. Identity records cannot be ingested as email files.")
    if "driving licence" in text_lower or "driving license" in text_lower:
        return ("Driving License", "Driving License document detected. Identity records cannot be ingested as email files.")
    if "election commission of india" in text_lower or "voter identity card" in text_lower:
        return ("Voter ID", "Voter Identity Card detected. Identity records cannot be ingested as email files.")

    return None


def validate_email_upload(
    file_obj_or_bytes: Any,
    filename: Optional[str] = None
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Perform multi-layer security & format validation on an uploaded email file.

    Checks performed:
    1. Empty file check
    2. File size limit enforcement
    3. Filename & extension analysis (must end in .eml, blocking PDFs, images, executables, double-exts)
    4. Binary magic-byte inspection (blocking .exe MZ headers, ELF, Mach-O, archives, PDFs, images)
    5. Null-byte density inspection (ensuring content is text, not binary)
    6. Identity document detection (blocking Aadhaar cards, PAN cards, etc.)
    7. RFC 822 / MIME email structure verification (detecting valid email headers and email addresses)

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
    bare_ext = ext.lstrip(".")

    if ext not in ALLOWED_EXTENSIONS:
        if bare_ext in DANGEROUS_EXTENSIONS:
            return (
                False,
                f"Security Violation: '{clean_fname}' is an executable or dangerous file type ({ext}). "
                f"Only RFC 822 email files (.eml) are permitted for forensic analysis.",
                {**details, "code": "EXECUTABLE_FILE_BLOCKED", "blocked_ext": ext}
            )
        if bare_ext in IMAGE_EXTENSIONS:
            return (
                False,
                f"Image File Rejected: '{clean_fname}' is an image file ({ext}). "
                f"Aadhaar card photos, screenshots, and graphic files cannot be analyzed directly as email messages. "
                f"Please upload a standard RFC 822 email file (.eml).",
                {**details, "code": "IMAGE_FILE_REJECTED", "blocked_ext": ext}
            )
        if bare_ext in DOCUMENT_EXTENSIONS:
            return (
                False,
                f"Document Format Rejected: '{clean_fname}' is a document ({ext}). "
                f"Aadhaar card PDFs, spreadsheets, and office files cannot be ingested. "
                f"Only RFC 822 email files (.eml) are supported for forensic investigation.",
                {**details, "code": "DOCUMENT_FILE_REJECTED", "blocked_ext": ext}
            )
        return (
            False,
            f"Unsupported file format '{ext or 'unknown'}'. "
            f"Only RFC 822 email files (.eml) are supported for forensic investigation.",
            {**details, "code": "INVALID_EXTENSION", "allowed": [".eml"]}
        )

    # 5. Multi-Extension & Double Extension Defense (e.g., payload.exe.eml, aadhaar.pdf.eml)
    tokens = [t.lower() for t in clean_fname.split(".")]
    if len(tokens) > 2:
        inner_extensions = set(tokens[1:-1])
        conflicting_dangerous = inner_extensions.intersection(DANGEROUS_EXTENSIONS)
        if conflicting_dangerous:
            conf_ext = list(conflicting_dangerous)[0]
            return (
                False,
                f"Security Violation: Double extension detected with dangerous payload signature (.{conf_ext}). "
                f"Disguised executable files are strictly prohibited.",
                {**details, "code": "DISGUISED_EXECUTABLE_BLOCKED", "dangerous_inner_ext": conf_ext}
            )
        conflicting_docs = inner_extensions.intersection(DOCUMENT_EXTENSIONS.union(IMAGE_EXTENSIONS))
        if conflicting_docs:
            conf_ext = list(conflicting_docs)[0]
            return (
                False,
                f"Security Violation: Double extension detected with document/image signature (.{conf_ext}.eml). "
                f"Renamed documents and identity files are prohibited.",
                {**details, "code": "DISGUISED_DOCUMENT_BLOCKED", "inner_ext": conf_ext}
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

    # WebP check (RIFF....WEBP)
    if header_chunk_512.startswith(b"RIFF") and len(header_chunk_512) >= 12 and header_chunk_512[8:12] == b"WEBP":
        return (
            False,
            "Security Rejection: WebP image binary detected. Images cannot be analyzed as email files.",
            {**details, "code": "IMAGE_MAGIC_BYTES"}
        )

    # Executable search: If MZ is within first 16 bytes
    if b"MZ" in header_chunk_512[:16]:
        return (
            False,
            "Security Rejection: Executable binary signature (MZ / PE) detected. Executables cannot be analyzed as emails.",
            {**details, "code": "EXECUTABLE_MAGIC_BYTES"}
        )

    # 7. Null-Byte Density Check
    sample_chunk = raw_bytes[:min(4096, file_size)]
    null_count = sample_chunk.count(b"\x00")
    if len(sample_chunk) > 0 and (null_count / len(sample_chunk)) > 0.01:
        return (
            False,
            "Binary File Rejected: The uploaded file contains binary byte sequences and is not a valid text-based email.",
            {**details, "code": "BINARY_FILE_REJECTED", "null_byte_ratio": null_count / len(sample_chunk)}
        )

    # 8. Decode content for Text & Header verification
    try:
        header_text = sample_chunk.decode("utf-8", errors="replace")
    except Exception:
        header_text = sample_chunk.decode("latin-1", errors="replace")

    # 9. Identity Document Inspection (Aadhaar / PAN check)
    id_doc = check_identity_document(header_text)
    headers_found = EMAIL_HEADER_PATTERN.findall(header_text)
    from_matches = re.findall(r"(?im)^From\s*:\s*(.+)$", header_text)
    has_valid_email_from = any("@" in f for f in from_matches)

    if id_doc:
        doc_type, doc_msg = id_doc
        # If text is an Aadhaar card without legitimate RFC email headers and sender email
        if not (has_valid_email_from and len(headers_found) >= 2):
            return (
                False,
                f"Identity Document Rejected: {doc_msg}",
                {**details, "code": "IDENTITY_DOCUMENT_REJECTED", "doc_type": doc_type}
            )

    # 10. RFC 822 / MIME Email Header Structure Verification
    if not headers_found:
        return (
            False,
            "Invalid Email Structure: The uploaded file does not contain valid RFC 822 email headers "
            "(e.g., From, To, Subject, Date, Received). Non-email documents and identity cards cannot be analyzed.",
            {**details, "code": "INVALID_EMAIL_HEADERS"}
        )

    # Prevent false positives where a letter or postal document has a lonely 'To:' line without any email address
    distinct_headers = set(h.lower().rstrip(":") for h in headers_found)
    has_email_addr = bool(re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", header_text))
    if len(distinct_headers) == 1 and "to" in distinct_headers and not has_email_addr:
        return (
            False,
            "Invalid Email Structure: The file contains a postal recipient ('To:') but lacks RFC 822 email headers (From, Subject, Date) and email addresses.",
            {**details, "code": "INVALID_EMAIL_HEADERS"}
        )

    details["headers_found_sample"] = headers_found[:5]
    details["is_valid"] = True
    return True, None, details


def validate_email_text_payload(text_content: Optional[str]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Validate raw pasted email text content from textarea or JSON payload.
    Ensures it is non-empty, contains readable text, has email structure,
    and is not an identity document (Aadhaar, PAN) or binary payload.
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

    # Identity document detection (Aadhaar / PAN card text)
    id_doc = check_identity_document(clean_text)
    from_matches = re.findall(r"(?im)^From\s*:\s*(.+)$", clean_text)
    has_valid_email_from = any("@" in f for f in from_matches)

    if id_doc and not has_valid_email_from:
        doc_type, doc_msg = id_doc
        return (
            False,
            f"Identity Document Rejected: {doc_msg}",
            {"code": "IDENTITY_DOCUMENT_REJECTED", "doc_type": doc_type}
        )

    # Check email headers or email addresses
    headers_found = EMAIL_HEADER_PATTERN.findall(clean_text[:2048])
    has_email_addr = bool(re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", clean_text))

    if not headers_found and not has_email_addr:
        return (
            False,
            "Invalid Email Content: The pasted text does not resemble an email message. "
            "It lacks RFC email headers (From, To, Subject) and standard email addresses.",
            {"code": "INVALID_EMAIL_CONTENT"}
        )

    return True, None, {"length": len(clean_text), "is_valid": True, "headers_count": len(headers_found)}
