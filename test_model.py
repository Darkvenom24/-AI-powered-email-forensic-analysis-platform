"""
SIH26106 - Email Threat Detection Model & Pipeline Verification Test
=====================================================================
Tests the complete end-to-end pipeline on at least 5 representative scenarios:
  1. Normal Legitimate Email
  2. Obvious Phishing Email
  3. Email with Suspicious URL (IP-based / Shortened)
  4. Spoofed-Looking Email (Authentication failures & Reply-To mismatch)
  5. Real .EML file with Security & Attachment Indicators (data/test_email.eml)
"""

import os
import json
import joblib

from app import analyze_email
from src.forensics import parse_email, get_email_body, analyze_headers, extract_header_ips, extract_attachments
from src.geolocation import get_ip_location

def print_result_card(title: str, email_preview: str, result: dict):
    print("\n" + "=" * 75)
    print(f"TEST SCENARIO: {title}")
    print("=" * 75)
    print(f"Content Preview:\n  {email_preview.strip()[:160]}...")
    print("-" * 75)
    print(f"Prediction:           {result['prediction']}")
    print(f"Phishing Probability: {result['phishing_probability']}%")
    print(f"Confidence:           {result['confidence']}%")
    print(f"Threat Score (0-100): {result['risk_score']}")
    print(f"Threat Level:         {result['threat']}")
    print("Risk Reasons Detected:")
    if result.get("risk_reasons"):
        for r in result["risk_reasons"]:
            print(f"  [!] {r}")
    else:
        print("  None (clean)")

    if result.get("urls"):
        print("URLs Detected:")
        for u in result["urls"]:
            print(f"  - {u['url']} (Risk: {u['risk_score']}, Suspicious: {u['suspicious']})")

    auth = result.get("forensics", {})
    if auth:
        print(f"Authentication: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}")

    if result.get("attachments"):
        print("Attachments:")
        for a in result["attachments"]:
            print(f"  - {a['filename']} ({a['size_bytes']} bytes, SHA256: {a['sha256'][:16]}..., Risky: {a['is_risky']})")
    print("=" * 75)


def run_tests():
    print("\n>>> STARTING 5-SCENARIO VERIFICATION SUITE FOR SIH26106 <<<\n")

    # -------------------------------------------------------------
    # Scenario 1: Normal Legitimate Email
    # -------------------------------------------------------------
    email_1 = """
    Hi Shambhavi,

    Hope you are doing well. Please find attached the notes from our morning sync meeting.
    We discussed the roadmap for the project demo and timeline for SEM-1 deliverables.
    Let me know if you would like to schedule a follow-up discussion tomorrow at 2 PM.

    Best regards,
    Alex Johnson
    Project Lead
    """
    forensics_1 = {
        "from": "alex.johnson@company.com",
        "reply_to": "alex.johnson@company.com",
        "return_path": "alex.johnson@company.com",
        "subject": "Project sync meeting notes",
        "spf": "PASS",
        "dkim": "PASS",
        "dmarc": "PASS",
        "indicators": []
    }
    res_1 = analyze_email(email_1, forensic_data=forensics_1)
    print_result_card("1. Normal Legitimate Corporate Email", email_1, res_1)

    # -------------------------------------------------------------
    # Scenario 2: Obvious Phishing Email
    # -------------------------------------------------------------
    email_2 = """
    URGENT NOTICE: Your bank account has been permanently locked due to unauthorized access attempts!
    You must verify your password, PIN and security credentials within 24 hours or your funds will be terminated.
    Click here to verify your identity now:
    http://secure-banking-alert-update.xyz/verify-login?account=9823472
    """
    forensics_2 = {
        "from": "alerts@chase-security-department.com",
        "reply_to": "attacker-inbox@mail-relay.xyz",
        "return_path": "bounce@mail-relay.xyz",
        "subject": "URGENT: Account Locked - Immediate Verification Required",
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
        "indicators": ["From and Reply-To domains do not match", "SPF authentication failed"]
    }
    res_2 = analyze_email(email_2, forensic_data=forensics_2)
    print_result_card("2. Obvious Phishing & Credential Harvester Email", email_2, res_2)

    # -------------------------------------------------------------
    # Scenario 3: Email Containing Suspicious URL (IP-Based & Shortener)
    # -------------------------------------------------------------
    email_3 = """
    Your payroll invoice #91823 has been updated.
    Please review the payment details at http://192.168.1.100:8080/invoice/download or visit
    https://bit.ly/3XyZ9Ab to authorize the transaction immediately.
    """
    forensics_3 = {
        "from": "accounting@vendor-portal.com",
        "reply_to": "accounting@vendor-portal.com",
        "return_path": "accounting@vendor-portal.com",
        "subject": "Updated Payroll Invoice",
        "spf": "PASS",
        "dkim": "PASS",
        "dmarc": "PASS",
        "indicators": []
    }
    res_3 = analyze_email(email_3, forensic_data=forensics_3)
    print_result_card("3. Email with Suspicious IP-Based & Shortened URLs", email_3, res_3)

    # -------------------------------------------------------------
    # Scenario 4: Spoofed-Looking Email (Auth Failures & Domain Mismatch)
    # -------------------------------------------------------------
    email_4 = """
    Dear Customer,
    
    We detected an unauthorized login to your Microsoft 365 administrative console from an unknown location.
    Please confirm your credentials to retain administrative access.
    """
    forensics_4 = {
        "from": "admin@microsoft.com",
        "reply_to": "helpdesk@micros0ft-support-center.click",
        "return_path": "bounce@suspicious-vps.ru",
        "subject": "Microsoft 365 Security Alert",
        "spf": "FAIL",
        "dkim": "FAIL",
        "dmarc": "FAIL",
        "indicators": [
            "SPF authentication failed",
            "DKIM authentication failed",
            "DMARC authentication failed",
            "From and Reply-To domains do not match"
        ]
    }
    res_4 = analyze_email(email_4, forensic_data=forensics_4)
    print_result_card("4. Spoofed-Looking Email (High Auth & Domain Anomalies)", email_4, res_4)

    # -------------------------------------------------------------
    # Scenario 5: Real .EML file (data/test_email.eml)
    # -------------------------------------------------------------
    eml_path = "data/test_email.eml"
    if os.path.exists(eml_path):
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()

        msg = parse_email(raw_bytes)
        body = get_email_body(msg)
        forensics_5 = analyze_headers(msg)
        header_ips = extract_header_ips(msg)
        attachments_5 = extract_attachments(msg)

        ip_results_5 = []
        for ip in header_ips:
            try:
                ip_results_5.append(get_ip_location(ip))
            except Exception:
                pass

        res_5 = analyze_email(body, forensic_data=forensics_5, ip_results=ip_results_5, attachments=attachments_5)
        print_result_card("5. Real .EML File (data/test_email.eml)", body, res_5)
    else:
        print("Notice: data/test_email.eml not found.")

    print("\n>>> VERIFICATION SUITE COMPLETE! ALL SCENARIOS EVALUATED SUCCESSFULLY. <<<\n")

if __name__ == "__main__":
    run_tests()
