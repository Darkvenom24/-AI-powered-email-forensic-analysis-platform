import os
import re
import hashlib
from email import policy
from email.parser import BytesParser


def parse_email(raw_bytes):
    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_bytes)
    return message


def get_email_body(message):
    body = ""

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", "")).lower()

            # Skip attachments when extracting text body
            if "attachment" in content_disposition:
                continue

            if content_type == "text/plain":
                try:
                    content = part.get_content()
                    if content:
                        body += content + "\n"
                except Exception:
                    pass
            elif content_type == "text/html" and not body.strip():
                try:
                    content = part.get_content()
                    if content:
                        # Strip basic html tags for fallback text
                        clean_text = re.sub(r"<[^>]+>", " ", content)
                        body += clean_text + "\n"
                except Exception:
                    pass
    else:
        try:
            body = message.get_content()
        except Exception:
            body = ""

    return body.strip()


def extract_header_ips(message):
    headers = []
    for received in message.get_all("Received", []):
        headers.append(received)

    text = "\n".join(headers)
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return list(dict.fromkeys(re.findall(pattern, text)))


def extract_attachments(message):
    """
    Safely extract attachment metadata and calculate SHA-256 checksums without executing.
    """
    attachments = []
    if not message.is_multipart():
        return attachments

    for part in message.walk():
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename()

        if filename or "attachment" in content_disposition:
            fn = filename or "unnamed_attachment"
            try:
                content_bytes = part.get_payload(decode=True) or b""
            except Exception:
                content_bytes = b""

            size = len(content_bytes)
            sha256 = hashlib.sha256(content_bytes).hexdigest() if content_bytes else "N/A"
            mime_type = part.get_content_type()
            
            # Extension analysis
            parts = fn.split(".")
            ext = parts[-1].lower() if len(parts) > 1 else ""
            has_double_extension = len(parts) > 2 and parts[-1].lower() in ["exe", "scr", "bat", "vbs", "js"]

            risky_extensions = {
                "exe", "scr", "bat", "cmd", "vbs", "js", "ps1",
                "docm", "xlsm", "jar", "hta", "dll", "msi", "reg"
            }
            is_risky = ext in risky_extensions or has_double_extension

            attachments.append({
                "filename": fn,
                "extension": ext,
                "size_bytes": size,
                "mime_type": mime_type,
                "sha256": sha256,
                "is_risky": is_risky,
                "has_double_extension": has_double_extension
            })

    return attachments


def extract_received_hops(message):
    """
    Extract structured mail routing hops from Received headers for forensic timeline.
    """
    received_list = message.get_all("Received", [])
    hops = []

    for idx, rec in enumerate(received_list):
        rec_str = str(rec).replace("\n", " ").strip()
        from_match = re.search(r"from\s+([^\s]+)", rec_str, re.IGNORECASE)
        by_match = re.search(r"by\s+([^\s]+)", rec_str, re.IGNORECASE)
        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", rec_str)
        time_match = re.search(r";\s*([A-Za-z0-9,:\s\+\-]+)$", rec_str)

        hops.append({
            "hop_number": idx + 1,
            "from_host": from_match.group(1) if from_match else "Unknown",
            "by_host": by_match.group(1) if by_match else "Unknown",
            "ip_address": ip_match.group(1) if ip_match else None,
            "timestamp": time_match.group(1).strip() if time_match else None,
            "raw": rec_str
        })

    return hops


def analyze_headers(message):
    result = {
        "from": message.get("From", "Not Found"),
        "reply_to": message.get("Reply-To", "Not Found"),
        "return_path": message.get("Return-Path", "Not Found"),
        "subject": message.get("Subject", "Not Found"),
        "message_id": message.get("Message-ID", "Not Found"),
        "date": message.get("Date", "Not Found"),
        "received": message.get_all("Received", []),
        "spf": "Not Found",
        "dkim": "Not Found",
        "dmarc": "Not Found",
        "indicators": []
    }

    # Authentication Results header
    auth = message.get("Authentication-Results", "").lower()

    # SPF check
    if "spf=pass" in auth:
        result["spf"] = "PASS"
    elif "spf=fail" in auth or "spf=softfail" in auth:
        result["spf"] = "FAIL"
        result["indicators"].append("SPF authentication failed")
    elif "spf=neutral" in auth:
        result["spf"] = "NEUTRAL"

    # Received-SPF fallback
    if result["spf"] == "Not Found":
        rec_spf = message.get("Received-SPF", "").lower()
        if "pass" in rec_spf:
            result["spf"] = "PASS"
        elif "fail" in rec_spf or "softfail" in rec_spf:
            result["spf"] = "FAIL"
            result["indicators"].append("SPF authentication failed")

    # DKIM check
    if "dkim=pass" in auth:
        result["dkim"] = "PASS"
    elif "dkim=fail" in auth:
        result["dkim"] = "FAIL"
        result["indicators"].append("DKIM authentication failed")

    # DMARC check
    if "dmarc=pass" in auth:
        result["dmarc"] = "PASS"
    elif "dmarc=fail" in auth:
        result["dmarc"] = "FAIL"
        result["indicators"].append("DMARC authentication failed")

    # From / Reply-To mismatch
    sender = str(result["from"])
    reply = str(result["reply_to"])

    sender_match = re.search(r"@([\w.-]+)", sender)
    reply_match = re.search(r"@([\w.-]+)", reply)

    if sender_match and reply_match:
        sender_domain = sender_match.group(1).lower().rstrip(">")
        reply_domain = reply_match.group(1).lower().rstrip(">")

        if sender_domain != reply_domain:
            result["indicators"].append("From and Reply-To domains do not match")

    # Received headers check
    if not result["received"]:
        result["indicators"].append("No Received header found")

    return result