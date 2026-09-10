"""
SIH26106 - AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
============================================================================================
Backend Flask Web Application & Threat Scoring Engine.

Flow:
  RAW EMAIL / EMAIL TEXT
          ↓
    EMAIL PARSING
          ↓
  FEATURE EXTRACTION
          ↓
TF-IDF + ML CLASSIFIER
          ↓
 PHISHING PROBABILITY
          ↓
URL / HEADER / AUTHENTICATION ANALYSIS
          ↓
 THREAT SCORE (0–100)
          ↓
LOW / MEDIUM / HIGH RISK
"""

import os
import re
import json
import joblib
import pandas as pd
from flask import Flask, render_template, request, session, send_file

from src.url_analyzer import extract_urls, analyze_url
from src.forensics import (
    parse_email,
    get_email_body,
    analyze_headers,
    extract_header_ips,
    extract_attachments
)
from src.geolocation import get_ip_location
from src.pdf_report import generate_pdf_report
from src.ioc_extractor import extract_iocs
from src.attachment_analyzer import analyze_email_attachments
from src.forensic_timeline import build_forensic_timeline
from src.database import (
    initialize_database,
    save_investigation,
    get_all_investigations,
    get_investigation,
    get_investigation_stats
)

# ============================================================
# FLASK APPLICATION SETUP
# ============================================================

app = Flask(__name__)

# Security Configuration
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret-key-sih26106"
)

# Maximum HTTP request size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
MAX_EMAIL_FILE_SIZE = 5 * 1024 * 1024

# ============================================================
# LOAD PRIMARY ML MODEL (TF-IDF + LOGISTIC REGRESSION)
# ============================================================

MODEL_PATH = "models/email_threat_model.pkl"

try:
    model = joblib.load(MODEL_PATH)
    print(f"ML threat model loaded successfully from {MODEL_PATH}!")
    if hasattr(model, "classes_"):
        print(f"Model classes: {model.classes_}")
except Exception as e:
    model = None
    print(f"WARNING: Failed to load ML model: {e}")

# ============================================================
# LOAD MODEL PERFORMANCE METRICS
# ============================================================

METRICS_PATH = "data/model_metrics.json"

try:
    with open(METRICS_PATH, "r", encoding="utf-8") as f:
        model_metrics = json.load(f)
    print("Model metrics loaded successfully!")
except Exception as e:
    print(f"Warning loading model metrics: {e}")
    model_metrics = {}

# ============================================================
# LOAD THREAT INTELLIGENCE DATASETS (M6 Threat Feeds)
# ============================================================

KNOWN_MALICIOUS_IPS = {}
KNOWN_PHISHING_URLS = {}
KNOWN_DOMAINS = {}
KNOWN_ATTACHMENT_HASHES = {}

def load_threat_intelligence():
    global KNOWN_MALICIOUS_IPS, KNOWN_PHISHING_URLS, KNOWN_DOMAINS, KNOWN_ATTACHMENT_HASHES

    # 1. IP and URL Threat Intelligence Excel (MISP/IPsum & OpenPhish)
    excel_path = "data/M6_IP_URL_Threat_Intelligence_Dataset.xlsx"
    if os.path.exists(excel_path):
        try:
            ip_df = pd.read_excel(excel_path, sheet_name="IP_Detection")
            for _, r in ip_df.iterrows():
                ip = str(r.get("ip_address", "")).strip()
                if ip and ip != "nan":
                    KNOWN_MALICIOUS_IPS[ip] = {
                        "source": str(r.get("source", "IPsum via MISP Level 6")),
                        "confidence": str(r.get("confidence", "High"))
                    }

            url_df = pd.read_excel(excel_path, sheet_name="Phishing_URL_Detection")
            for _, r in url_df.iterrows():
                u = str(r.get("url", "")).strip().lower()
                if u and u != "nan":
                    KNOWN_PHISHING_URLS[u] = {
                        "source": str(r.get("source", "OpenPhish Community Feed")),
                        "confidence": str(r.get("confidence", "High"))
                    }
        except Exception as e:
            print(f"Notice: Loading Excel threat intelligence: {e}")

    # 2. Large URL Dataset (15,000 labeled URLs)
    url_csv = "data/M6_URL.csv"
    if os.path.exists(url_csv):
        try:
            m6_df = pd.read_csv(url_csv)
            for _, r in m6_df[m6_df["label"] == 1].iterrows():
                u = str(r.get("url", "")).strip().lower()
                if u and u not in KNOWN_PHISHING_URLS:
                    KNOWN_PHISHING_URLS[u] = {
                        "source": "M6 URL Threat Database",
                        "confidence": "High"
                    }
        except Exception as e:
            print(f"Notice: Loading M6_URL.csv: {e}")

    # 3. Domain & DNS Intelligence (10,000 domains)
    domain_csv = "data/M6_Domain_DNS_Final.csv"
    if os.path.exists(domain_csv):
        try:
            dom_df = pd.read_csv(domain_csv)
            for _, r in dom_df.iterrows():
                dom = str(r.get("domain", "")).strip().lower()
                if dom and dom != "nan":
                    KNOWN_DOMAINS[dom] = {
                        "label": int(r.get("label", 0)),
                        "has_spf": int(r.get("has_spf", 0)),
                        "has_dmarc": int(r.get("has_dmarc", 0)),
                        "mx_count": int(r.get("mx_count", 0)),
                        "domain_age_days": r.get("domain_age_days", 0)
                    }
        except Exception as e:
            print(f"Notice: Loading M6_Domain_DNS_Final.csv: {e}")

    # 4. Attachment Threat Signatures (Malware Hashes & Emotet Signatures)
    att_csv = "data/M6_Attachmen_Dataset.csv"
    if os.path.exists(att_csv):
        try:
            att_df = pd.read_csv(att_csv)
            for _, r in att_df[att_df["label"] == 1].iterrows():
                h = str(r.get("sha256", "")).strip().lower()
                if h and h != "nan":
                    KNOWN_ATTACHMENT_HASHES[h] = {
                        "signature": str(r.get("signature", "Known Malware")),
                        "filename": str(r.get("filename", "")),
                        "file_type": str(r.get("file_type", ""))
                    }
        except Exception as e:
            print(f"Notice: Loading M6_Attachmen_Dataset.csv: {e}")

    print(f"Threat Intelligence loaded: {len(KNOWN_MALICIOUS_IPS)} malicious IPs, "
          f"{len(KNOWN_PHISHING_URLS)} phishing URLs, {len(KNOWN_DOMAINS)} domains, "
          f"{len(KNOWN_ATTACHMENT_HASHES)} attachment signatures.")

load_threat_intelligence()

# ============================================================
# SECURITY / ERROR HANDLING HELPERS
# ============================================================

def is_valid_eml(message, raw_bytes):
    """Basic validation for uploaded .eml files."""
    if not raw_bytes or not raw_bytes.strip():
        return False

    common_headers = (
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID",
        "Reply-To",
        "Return-Path",
    )
    return any(message.get(header) for header in common_headers)


@app.errorhandler(413)
def request_too_large(error):
    return render_template(
        "index.html",
        result=None,
        error="File is too large. Maximum allowed size is 5 MB.",
        model_metrics=model_metrics
    ), 413


@app.errorhandler(500)
def internal_server_error(error):
    print(f"Internal server error: {error}")
    return render_template(
        "index.html",
        result=None,
        error="An internal error occurred. Please try again.",
        model_metrics=model_metrics
    ), 500


def extract_ips(text):
    """Extract IPv4 addresses from email text."""
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return list(dict.fromkeys(re.findall(pattern, text)))


# ============================================================
# CORE ANALYSIS PIPELINE & ENSEMBLE THREAT SCORING
# ============================================================

def analyze_email(
    email_text,
    forensic_data=None,
    ip_results=None,
    attachments=None,
    message=None
):
    """
    Complete email security pipeline:
    1. ML Phishing Probability via TF-IDF + Logistic Regression Pipeline
    2. URL & Domain Threat Intelligence Analysis
    3. Header & Authentication Forensics (SPF, DKIM, DMARC, Mismatch)
    4. Attachment Security Check (SHA-256 vs M6 Threat Database)
    5. Ensemble Threat Scoring (0–100) mapped to Low/Medium/High Risk
    """
    if model is None:
        raise RuntimeError("ML model is unavailable. Please check the model file.")

    if not isinstance(email_text, str) or not email_text.strip():
        raise ValueError("Email content cannot be empty.")

    # --------------------------------------------------------
    # 1. PRIMARY ML PREDICTION & PHISHING PROBABILITY
    # --------------------------------------------------------
    probas = model.predict_proba([email_text])[0]
    classes = list(model.classes_)

    phish_idx = classes.index("phishing") if "phishing" in classes else 0
    safe_idx = classes.index("safe") if "safe" in classes else 1
    
    # Safe class mapping for phishing probability (0.0 to 1.0)
    raw_phish_prob = float(probas[phish_idx])
    phishing_probability = round(raw_phish_prob * 100.0, 2)
    confidence = round(float(max(probas)) * 100.0, 2)

    pred_class = model.predict([email_text])[0].lower()
    if pred_class == "phishing":
        prediction_display = "PHISHING"
    elif pred_class == "spam":
        prediction_display = "SPAM"
    else:
        prediction_display = "SAFE"

    # --------------------------------------------------------
    # 2. URL ANALYSIS & THREAT INTELLIGENCE
    # --------------------------------------------------------
    urls = extract_urls(email_text)
    url_results = []
    known_threat_urls_set = set(KNOWN_PHISHING_URLS.keys())

    for url in urls:
        url_res = analyze_url(url, known_threat_urls=known_threat_urls_set)
        url_results.append(url_res)

    # --------------------------------------------------------
    # 3. IP EXTRACTION & IOC MATCHING
    # --------------------------------------------------------
    text_ips = extract_ips(email_text)
    all_ips = list(dict.fromkeys(text_ips + ([r.get("ip") for r in (ip_results or []) if r.get("ip")])))

    # --------------------------------------------------------
    # 3.1 IOC EXTRACTION
    # --------------------------------------------------------
    ioc_data = extract_iocs(email_text)

    # --------------------------------------------------------
    # 3.2 ATTACHMENT ANALYSIS
    # --------------------------------------------------------
    attachment_data = {
        "attachments": [],
        "attachment_count": 0,
        "suspicious_count": 0,
        "high_risk_count": 0,
        "medium_risk_count": 0,
        "has_attachments": False,
        "overall_risk": "LOW",
    }

    if message is None:
        try:
            message = parse_email(
                email_text.encode("utf-8", errors="ignore")
            )
        except Exception:
            message = None

    if message is not None:
        try:
            attachment_data = analyze_email_attachments(message)
        except Exception as attachment_error:
            print(f"Attachment analysis warning: {attachment_error}")

        if attachments is None:
            try:
                attachments = extract_attachments(message)
            except Exception:
                attachments = []

    # --------------------------------------------------------
    # 4. FORENSIC HEADERS
    # --------------------------------------------------------
    if forensic_data is None:
        try:
            msg = message or parse_email(email_text.encode("utf-8", errors="ignore"))
            forensic_data = analyze_headers(msg)
        except Exception:
            forensic_data = {
                "from": "Not Found",
                "reply_to": "Not Found",
                "return_path": "Not Found",
                "subject": "Not Found",
                "message_id": "Not Found",
                "received": [],
                "spf": "Not Found",
                "dkim": "Not Found",
                "dmarc": "Not Found",
                "indicators": []
            }

    # --------------------------------------------------------
    # 5. ENSEMBLE THREAT SCORING (0 to 100)
    # --------------------------------------------------------
    risk_reasons = []

    # ========================================================
    # 5.1 AI MODEL CONTRIBUTION (0–50 POINTS)
    # Direct proportion of phishing probability (no double-counting)
    # ========================================================
    ai_score = raw_phish_prob * 50.0

    if phishing_probability >= 70.0:
        risk_reasons.append(f"High phishing probability from ML model ({phishing_probability}%)")
    elif phishing_probability >= 40.0:
        risk_reasons.append(f"Moderate phishing probability from ML model ({phishing_probability}%)")
    elif pred_class == "spam":
        risk_reasons.append("Email text exhibits suspicious spam patterns")
    elif phishing_probability <= 15.0 and pred_class == "safe":
        # Low risk safe email
        pass

    # ========================================================
    # 5.2 URL / IOC CONTRIBUTION (0–25 POINTS)
    # ========================================================
    url_ioc_score = 0.0

    has_threat_url = False
    has_ip_url = False
    has_short_url = False
    has_suspicious_url = False

    for u in url_results:
        u_indicators = [ind.lower() for ind in u.get("indicators", [])]
        u_risk = u.get("risk_score", 0)

        # Check threat intelligence exact match
        if any("threat intelligence" in ind for ind in u_indicators) or u["url"].lower() in KNOWN_PHISHING_URLS:
            has_threat_url = True
        if any("ip address" in ind for ind in u_indicators):
            has_ip_url = True
        if any("shortened" in ind for ind in u_indicators):
            has_short_url = True
        if u_risk >= 20:
            has_suspicious_url = True

    if has_threat_url:
        url_ioc_score += 15.0
        risk_reasons.append("Known phishing URL detected in threat intelligence feed")
    elif has_ip_url:
        url_ioc_score += 10.0
        risk_reasons.append("URL contains IP address instead of domain name")
    elif has_short_url:
        url_ioc_score += 8.0
        risk_reasons.append("Suspicious shortened URL detected")
    elif has_suspicious_url:
        url_ioc_score += 6.0
        risk_reasons.append("Suspicious URL indicators detected")

    # Check IPs against Known Malicious IP threat intelligence
    matched_malicious_ips = []
    for ip in all_ips:
        if ip in KNOWN_MALICIOUS_IPS:
            matched_malicious_ips.append(ip)

    if matched_malicious_ips:
        url_ioc_score += 15.0
        risk_reasons.append(f"Known malicious IP address detected in threat intelligence feed: {', '.join(matched_malicious_ips[:2])}")

    # Check sender domain in M6 Domain DNS dataset
    sender_str = str(forensic_data.get("from", "")).lower()
    sender_dom_match = re.search(r"@([a-z0-9.\-]+)", sender_str)
    if sender_dom_match:
        s_dom = sender_dom_match.group(1).rstrip(">")
        if s_dom in KNOWN_DOMAINS:
            dom_info = KNOWN_DOMAINS[s_dom]
            if dom_info.get("label") == 1:
                url_ioc_score += 12.0
                risk_reasons.append(f"Sender domain '{s_dom}' flagged in phishing domain intelligence database")
            elif dom_info.get("mx_count") == 0:
                url_ioc_score += 5.0
                risk_reasons.append(f"Sender domain '{s_dom}' has no valid mail exchange (MX) DNS records")

    # Cap URL / IOC contribution at 25 points
    url_ioc_score = min(url_ioc_score, 25.0)

    # ========================================================
    # 5.3 EMAIL SECURITY / FORENSIC CONTRIBUTION (0–25 POINTS)
    # ========================================================
    auth_forensic_score = 0.0

    spf_status = str(forensic_data.get("spf", "Not Found")).upper()
    dkim_status = str(forensic_data.get("dkim", "Not Found")).upper()
    dmarc_status = str(forensic_data.get("dmarc", "Not Found")).upper()

    auth_failures = 0

    if spf_status == "FAIL":
        auth_failures += 1
        auth_forensic_score += 8.0
        risk_reasons.append("SPF authentication failed")

    if dkim_status == "FAIL":
        auth_failures += 1
        auth_forensic_score += 6.0
        risk_reasons.append("DKIM authentication failed")

    if dmarc_status == "FAIL":
        auth_failures += 1
        auth_forensic_score += 8.0
        risk_reasons.append("DMARC authentication failed")

    # Multiple authentication failures are strong evidence of spoofing
    if auth_failures >= 2:
        auth_forensic_score += 4.0
        risk_reasons.append("Multiple email authentication failures detected")

    # From / Reply-To mismatch
    forensic_indicators = forensic_data.get("indicators", []) or []
    mismatch = any("mismatch" in str(ind).lower() for ind in forensic_indicators)
    if mismatch:
        auth_forensic_score += 8.0
        risk_reasons.append("Sender and Reply-To domains do not match")

    # Attachment Security Risk
    if attachments:
        has_risky_att = False
        has_malware_hash = False
        for att in attachments:
            sha = att.get("sha256", "").lower()
            if sha in KNOWN_ATTACHMENT_HASHES:
                has_malware_hash = True
                sig = KNOWN_ATTACHMENT_HASHES[sha].get("signature", "Malware")
                risk_reasons.append(f"Attachment hash matched known malware signature ({sig})")
            elif att.get("is_risky"):
                has_risky_att = True

        if has_malware_hash:
            auth_forensic_score += 15.0
        elif has_risky_att:
            auth_forensic_score += 10.0
            risk_reasons.append("High-risk or executable attachment detected")

    # Cap Forensic / Auth contribution at 25 points
    auth_forensic_score = min(auth_forensic_score, 25.0)

    # ========================================================
    # 5.4 TOTAL THREAT SCORE & TIER MAPPING
    # 0–39: LOW RISK, 40–69: MEDIUM RISK, 70–100: HIGH RISK
    # ========================================================
    raw_total = ai_score + url_ioc_score + auth_forensic_score

    # False-positive protection: If high-confidence safe with clean security signals, clamp low
    if pred_class == "safe" and confidence >= 85 and not has_threat_url and not has_ip_url and auth_failures == 0 and not mismatch:
        raw_total = min(raw_total, 25.0)

    risk_score = int(round(min(max(raw_total, 0.0), 100.0)))

    if risk_score >= 70:
        threat = "HIGH RISK"
    elif risk_score >= 40:
        threat = "MEDIUM RISK"
    else:
        threat = "LOW RISK"

    # Deduplicate reasons while preserving order
    risk_reasons = list(dict.fromkeys(risk_reasons))
    if not risk_reasons and risk_score < 40:
        risk_reasons.append("Email passed core security and authentication checks")

    # --------------------------------------------------------
    # 6. FORENSIC TIMELINE
    # --------------------------------------------------------
    timeline = build_forensic_timeline(
        message=message,
        forensic_data=forensic_data,
        ioc_data=ioc_data,
        attachment_data=attachment_data,
        url_results=url_results,
        prediction=prediction_display,
        risk_score=risk_score,
        threat=threat,
    )

    # --------------------------------------------------------
    # 7. RETURN ENRICHED RESULT
    # --------------------------------------------------------
    return {
        "prediction": prediction_display,
        "phishing_probability": phishing_probability,
        "confidence": confidence,
        "risk_score": risk_score,
        "threat": threat,
        "risk_reasons": risk_reasons,
        "urls": url_results,
        "ips": all_ips,
        "forensics": forensic_data,
        "ip_results": ip_results or [],
        "iocs": ioc_data,
        "attachments": attachment_data,
        "timeline": timeline
    }


# ============================================================
# HOME & ANALYSIS ROUTE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    message = None

    if request.method == "POST":
        email_text = ""

        # 1. Pasted text input
        pasted_text = request.form.get("email_text", "").strip()
        if pasted_text:
            email_text = pasted_text

        # 2. .EML file upload
        uploaded_file = request.files.get("email_file")
        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename.strip()
            if not filename.lower().endswith(".eml"):
                error = "Only .eml files are allowed."
            else:
                try:
                    raw_bytes = uploaded_file.read()
                    if len(raw_bytes) > MAX_EMAIL_FILE_SIZE:
                        error = "Uploaded file is too large. Maximum allowed size is 5 MB."
                    elif not raw_bytes.strip():
                        error = "Uploaded file is empty."
                    else:
                        message = parse_email(raw_bytes)
                        if message is None or not is_valid_eml(message, raw_bytes):
                            error = "Invalid .eml file. No valid email headers were found."
                        else:
                            body = get_email_body(message)
                            if not body.strip():
                                body = raw_bytes.decode("utf-8", errors="replace")

                            if not body.strip():
                                error = "The email does not contain readable content."
                            else:
                                forensic_data = analyze_headers(message)
                                header_ips = extract_header_ips(message)
                                attachments = extract_attachments(message)

                                # Geolocation lookup for header routing IPs
                                ip_results = []
                                for ip in header_ips:
                                    try:
                                        location = get_ip_location(ip)
                                        if not isinstance(location, dict):
                                            location = {
                                                "ip": ip, "type": "Unknown",
                                                "country": "Unavailable", "city": "Unavailable",
                                                "region": "Unavailable", "organization": "Unavailable",
                                                "latitude": None, "longitude": None
                                            }
                                    except Exception:
                                        location = {
                                            "ip": ip, "type": "Unknown",
                                            "country": "Unavailable", "city": "Unavailable",
                                            "region": "Unavailable", "organization": "Unavailable",
                                            "latitude": None, "longitude": None
                                        }
                                    ip_results.append(location)

                                result = analyze_email(
                                    body,
                                    forensic_data=forensic_data,
                                    ip_results=ip_results,
                                    attachments=attachments,
                                    message=message
                                )

                except Exception as e:
                    print(f"File upload error: {e}")
                    error = "Unable to process the uploaded email. Please check the file."

        # 3. Analyze pasted plain text
        elif email_text and not error:
            try:
                try:
                    message = parse_email(
                        email_text.encode("utf-8", errors="ignore")
                    )
                except Exception as parse_error:
                    print(f"Pasted email parse warning: {parse_error}")
                    message = None

                result = analyze_email(
                    email_text,
                    message=message
                )
            except Exception as e:
                print(f"Text analysis error: {e}")
                error = "Email analysis failed. Please check the input."

        elif not email_text and not error:
            error = "Please upload an .eml file or paste email content."

        if result and not error:
            session["analysis_result"] = result

            try:
                forensic_info = result.get("forensics", {}) or {}
                sender = forensic_info.get("from", "")
                receiver = forensic_info.get("to", "")

                if not receiver and message is not None:
                    try:
                        receiver = message.get("To", "")
                    except Exception:
                        receiver = ""

                subject = forensic_info.get("subject", "")
                result["threat_level"] = result.get("threat", "UNKNOWN")

                case_id = save_investigation(
                    result=result,
                    sender=sender,
                    receiver=receiver,
                    subject=subject
                )
                session["case_id"] = case_id
                result["case_id"] = case_id
                print(f"Investigation saved successfully: {case_id}")
            except Exception as db_error:
                print(f"Database save warning: {db_error}")

    try:
        stats = get_investigation_stats()
    except Exception as stats_error:
        print(f"Statistics loading error: {stats_error}")
        stats = {
            "total": 0, "phishing": 0, "spam": 0, "safe": 0,
            "high_risk": 0, "medium_risk": 0, "low_risk": 0,
            "average_risk": 0
        }

    return render_template(
        "index.html",
        result=result,
        error=error,
        model_metrics=model_metrics,
        case_id=session.get("case_id"),
        stats=stats
    )


# ============================================================
# INVESTIGATION HISTORY
# ============================================================

@app.route("/history", methods=["GET"])
def investigation_history():
    try:
        investigations = get_all_investigations()
        return render_template(
            "history.html",
            investigations=investigations
        )
    except Exception as e:
        print(f"History loading error: {e}")
        return "Unable to load investigation history.", 500


# ============================================================
# INVESTIGATION DETAILS
# ============================================================

@app.route("/case/<case_id>", methods=["GET"])
def investigation_details(case_id):
    try:
        investigation = get_investigation(case_id)
        if not investigation:
            return "Investigation case not found.", 404
        return render_template(
            "case_details.html",
            investigation=investigation
        )
    except Exception as e:
        print(f"Case details error: {e}")
        return "Unable to load investigation details.", 500


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@app.route("/generate-report", methods=["GET"])
def generate_report():
    result = session.get("analysis_result")
    if not result:
        return "No analysis result available. Please analyze an email first."

    try:
        reports_folder = "reports"
        os.makedirs(reports_folder, exist_ok=True)
        pdf_path = os.path.join(reports_folder, "email_forensic_report.pdf")

        generate_pdf_report(result, pdf_path)

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name="email_forensic_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        print(f"PDF generation error: {e}")
        return "PDF report generation failed. Please try again after analyzing.", 500


# ============================================================
# APPLICATION RUNNER
# ============================================================

if __name__ == "__main__":
    try:
        initialize_database()
        print("Investigation database initialized successfully!")
    except Exception as db_error:
        print(f"WARNING: Database initialization failed: {db_error}")

    app.run(debug=False, port=5000)
