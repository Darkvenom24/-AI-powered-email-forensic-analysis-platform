from flask import Flask, render_template, request, session, send_file, jsonify, send_from_directory
try:
    from flask_cors import CORS
    has_cors = True
except ImportError:
    has_cors = False

try:
    import joblib
except ImportError:
    joblib = None
import re
import os
import tempfile
import json
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

from src.url_analyzer import extract_urls, analyze_url
from src.forensics import (
    parse_email,
    get_email_body,
    analyze_headers,
    extract_header_ips
)
from src.geolocation import get_ip_location
from src.pdf_report import generate_pdf_report
from src.ioc_extractor import extract_iocs
from src.attachment_analyzer import analyze_email_attachments
from src.forensic_timeline import build_forensic_timeline
from src.database import (
    save_investigation,
    get_all_investigations,
    get_investigation,
    get_investigation_stats,
    sync_sqlite_to_supabase
)
from src.supabase_client import (
    is_supabase_configured,
    test_connection as test_supabase_connection,
    get_supabase_credentials
)
from src.sample_presets import get_all_presets, get_preset

# ============================================================
# FLASK APP SETUP
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
if has_cors:
    try:
        CORS(app)
    except Exception:
        pass

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    return response

@app.before_request
def handle_options_request():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
        return response

@app.route("/static/<path:filename>")
def serve_static(filename):
    for folder in ["public/static", "static", "public"]:
        fdir = os.path.join(BASE_DIR, folder)
        target = os.path.join(fdir, filename)
        if os.path.exists(target):
            return send_from_directory(fdir, filename)
    return jsonify({"error": f"Static file {filename} not found"}), 404

@app.route("/style.css")
def serve_root_style():
    for folder in ["public", "static", "public/static"]:
        fpath = os.path.join(BASE_DIR, folder, "style.css")
        if os.path.exists(fpath):
            return send_file(fpath, mimetype="text/css")
    return jsonify({"error": "style.css not found"}), 404

@app.route("/dashboard.js")
def serve_root_js():
    for folder in ["public", "static", "public/static"]:
        fpath = os.path.join(BASE_DIR, folder, "dashboard.js")
        if os.path.exists(fpath):
            return send_file(fpath, mimetype="application/javascript")
    return jsonify({"error": "dashboard.js not found"}), 404

import urllib.parse

class VercelPathFixMiddleware:
    """Ensures paths passed through Vercel rewrites or direct invocations map correctly to Flask routes."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        qs = environ.get("QUERY_STRING", "")
        if "__orig_path=" in qs:
            parsed = urllib.parse.parse_qs(qs, keep_blank_values=True)
            if "__orig_path" in parsed and parsed["__orig_path"]:
                target = parsed.pop("__orig_path")[0]
                if not target.startswith("/"):
                    target = "/" + target
                environ["PATH_INFO"] = target
                environ["QUERY_STRING"] = urllib.parse.urlencode(parsed, doseq=True)
        else:
            path = environ.get("PATH_INFO", "")
            if path.startswith("/api/index.py"):
                clean = path[len("/api/index.py"):]
                environ["PATH_INFO"] = clean if clean else "/"
            elif path.startswith("/api/index"):
                clean = path[len("/api/index"):]
                if clean and clean.startswith("/"):
                    environ["PATH_INFO"] = clean
                elif not clean:
                    environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

SECRET_KEY_FALLBACK = "sih26106-forensics-production-secret-key-32bytes"
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or SECRET_KEY_FALLBACK
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or SECRET_KEY_FALLBACK

# Maximum HTTP request size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# ============================================================
# LOAD ML MODEL
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "email_threat_model.pkl")
model = None

try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("ML model loaded successfully!")
    else:
        print(f"Warning: Model file {MODEL_PATH} not found.")
except Exception as e:
    print(f"WARNING: Failed to load ML model: {e}")

# ============================================================
# LOAD ML MODEL PERFORMANCE METRICS
# ============================================================

METRICS_PATH = os.path.join(BASE_DIR, "data", "model_metrics.json")
model_metrics = {}

try:
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            model_metrics = json.load(f)
        print("Model metrics loaded successfully!")
except Exception as e:
    print(f"Failed to load model metrics: {e}")

MAX_EMAIL_FILE_SIZE = 10 * 1024 * 1024


def is_valid_eml(message, raw_bytes):
    """Basic validation for uploaded .eml files."""
    if not raw_bytes or not raw_bytes.strip():
        return False
    common_headers = (
        "From", "To", "Subject", "Date", "Message-ID", "Reply-To", "Return-Path"
    )
    return any(message.get(header) for header in common_headers)


def extract_ips(text):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return re.findall(pattern, text)


# ============================================================
# ENHANCED EMAIL ANALYSIS PIPELINE
# ============================================================

def analyze_email(
    email_text,
    forensic_data=None,
    ip_results=None,
    message=None
):
    """
    Complete analysis pipeline combining AI/ML, Heuristics,
    Headers, Geolocation, Timeline, and Graph generation.
    """
    if not isinstance(email_text, str) or not email_text.strip():
        raise ValueError("Email content cannot be empty.")

    # 1. ML Threat Detection
    prediction = "SAFE"
    confidence = 80.0
    phishing_prob = 0.15

    if model is not None:
        try:
            pred_raw = model.predict([email_text])[0]
            probabilities = model.predict_proba([email_text])[0]
            prediction = str(pred_raw).upper()
            confidence = round(max(probabilities) * 100, 2)
            
            # Map classes to phishing probability
            if hasattr(model, "classes_"):
                classes = [str(c).lower() for c in model.classes_]
                if "phishing" in classes:
                    idx = classes.index("phishing")
                    phishing_prob = round(float(probabilities[idx]), 3)
                elif "spam" in classes:
                    idx = classes.index("spam")
                    phishing_prob = round(float(probabilities[idx]) * 0.7, 3)
                else:
                    phishing_prob = round(1.0 - float(probabilities[0]), 3)
            else:
                phishing_prob = round(confidence / 100 if prediction == "PHISHING" else 0.1, 3)
        except Exception as ml_err:
            print(f"ML prediction warning: {ml_err}")
    else:
        # Fallback keyword-based prediction
        text_lower = email_text.lower()
        if any(w in text_lower for w in ["urgent", "password", "suspended", "wire transfer", "verify", "invoice"]):
            prediction = "PHISHING"
            confidence = 88.5
            phishing_prob = 0.88

    # 2. URL Analysis
    urls = extract_urls(email_text)
    url_results = []
    suspicious_url_count = 0
    severe_url_count = 0

    for url in urls:
        url_res = analyze_url(url)
        url_results.append(url_res)
        if url_res.get("suspicious", False):
            suspicious_url_count += 1
        if int(url_res.get("risk_score", 0) or 0) >= 50:
            severe_url_count += 1

    # 3. IP Extraction
    ips = extract_ips(email_text)

    # 4. IOC Extraction
    ioc_data = extract_iocs(email_text)

    # 5. Attachment Analysis
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
            message = parse_email(email_text.encode("utf-8", errors="ignore"))
        except Exception:
            message = None

    if message is not None:
        try:
            attachment_data = analyze_email_attachments(message)
        except Exception as att_err:
            print(f"Attachment analysis error: {att_err}")

    # 6. Forensic Header Analysis
    if forensic_data is None:
        if message is not None:
            try:
                forensic_data = analyze_headers(message)
            except Exception:
                forensic_data = None

        if forensic_data is None:
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

    # 7. Risk Scoring Engine (0-100)
    risk_score = 0
    risk_reasons = []
    prediction_lower = prediction.lower()

    # Normalize authentication
    spf_status = str(forensic_data.get("spf", "Not Found")).lower()
    dkim_status = str(forensic_data.get("dkim", "Not Found")).lower()
    dmarc_status = str(forensic_data.get("dmarc", "Not Found")).lower()

    # 7.1 ML Contribution
    if prediction_lower == "phishing":
        risk_score += 45
        risk_reasons.append("AI model classified email body as PHISHING")
    elif prediction_lower == "spam":
        risk_score += 25
        risk_reasons.append("AI model classified email as SPAM")
    else:
        risk_reasons.append("AI text classification: SAFE")

    if confidence >= 85 and prediction_lower in ["phishing", "spam"]:
        risk_score += 10
        risk_reasons.append(f"High ML prediction confidence ({confidence}%)")

    # 7.2 URL Contribution
    if suspicious_url_count > 0:
        risk_score += min(suspicious_url_count * 12, 25)
        risk_reasons.append(f"{suspicious_url_count} suspicious URL(s) detected in email body")
    if severe_url_count > 0:
        risk_score += 10
        risk_reasons.append("High-severity malicious link pattern found")

    # 7.3 Authentication Checks
    auth_failures = 0
    if "fail" in spf_status:
        auth_failures += 1
        risk_score += 12
        risk_reasons.append("SPF sender verification FAILED")
    if "fail" in dkim_status:
        auth_failures += 1
        risk_score += 8
        risk_reasons.append("DKIM cryptographic signature verification FAILED")
    if "fail" in dmarc_status:
        auth_failures += 1
        risk_score += 10
        risk_reasons.append("DMARC alignment policy check FAILED")

    if auth_failures >= 2:
        risk_score += 5
        risk_reasons.append("Multiple email authentication protocol failures")

    # 7.4 From / Reply-To Mismatch (BEC indicator)
    forensic_indicators = forensic_data.get("indicators", []) or []
    mismatch_detected = any(
        "reply-to" in str(ind).lower() and ("mismatch" in str(ind).lower() or "different" in str(ind).lower())
        for ind in forensic_indicators
    )
    if mismatch_detected:
        risk_score += 15
        risk_reasons.append("From and Reply-To domains do not match (Spoofing/BEC indicator)")

    # 7.5 Attachment Risk
    high_att = int(attachment_data.get("high_risk_count", 0) or 0)
    med_att = int(attachment_data.get("medium_risk_count", 0) or 0)
    if high_att > 0:
        risk_score += min(high_att * 25, 35)
        risk_reasons.append(f"{high_att} high-risk executable/script attachment(s) identified")
    elif med_att > 0:
        risk_score += min(med_att * 12, 18)
        risk_reasons.append(f"{med_att} archive/disk-image attachment(s) detected")

    # 7.6 False Positive Damping
    if prediction_lower == "safe" and confidence >= 85 and suspicious_url_count == 0 and auth_failures == 0 and high_att == 0:
        risk_score = min(risk_score, 15)
        risk_reasons.append("High-confidence verified safe email")

    # Final Risk Bounds
    risk_score = max(0, min(int(risk_score), 100))

    if risk_score >= 70:
        threat = "HIGH RISK"
    elif risk_score >= 40:
        threat = "MEDIUM RISK"
    else:
        threat = "LOW RISK"

    risk_reasons = list(dict.fromkeys(risk_reasons))

    # 8. Timeline
    timeline = build_forensic_timeline(
        message=message,
        forensic_data=forensic_data,
        ioc_data=ioc_data,
        attachment_data=attachment_data,
        url_results=url_results,
        prediction=prediction,
        risk_score=risk_score,
        threat=threat,
    )

    # 9. Relationship Graph Construction (Sender -> Domain -> IP -> URL -> Attachment)
    sender_val = forensic_data.get("from", "Unknown Sender")
    domain_val = "unknown-domain.com"
    if "@" in sender_val:
        domain_val = sender_val.split("@")[-1].strip(">").strip()
    elif ioc_data.get("domains"):
        domain_val = ioc_data["domains"][0]

    primary_ip = "127.0.0.1"
    if ip_results and len(ip_results) > 0:
        primary_ip = ip_results[0].get("ip", "127.0.0.1")
    elif ips:
        primary_ip = ips[0]

    primary_url = urls[0] if urls else "None"
    att_name = attachment_data["attachments"][0]["filename"] if attachment_data.get("attachments") else "None"

    graph_nodes = [
        {"id": "sender", "label": sender_val[:24], "type": "sender", "full": sender_val},
        {"id": "domain", "label": domain_val[:20], "type": "domain", "full": domain_val},
        {"id": "ip", "label": primary_ip, "type": "ip", "full": primary_ip},
    ]
    graph_edges = [
        {"from": "sender", "to": "domain", "label": "sent from"},
        {"from": "domain", "to": "ip", "label": "relayed via"},
    ]

    if primary_url != "None":
        graph_nodes.append({"id": "url", "label": primary_url[:24], "type": "url", "full": primary_url})
        graph_edges.append({"from": "ip", "to": "url", "label": "hosts"})

    if att_name != "None":
        graph_nodes.append({"id": "attachment", "label": att_name[:20], "type": "attachment", "full": att_name})
        graph_edges.append({"from": "sender", "to": "attachment", "label": "contains"})

    # Key threat badges for UI matching image_3
    threat_indicators = []
    if "fail" in spf_status:
        threat_indicators.append({"label": "SPF Failed", "level": "danger"})
    if mismatch_detected:
        threat_indicators.append({"label": "From/Reply-To Mismatch", "level": "danger"})
    if suspicious_url_count > 0:
        threat_indicators.append({"label": "Suspicious URL", "level": "danger"})
    if high_att > 0:
        threat_indicators.append({"label": "Risky Attachment", "level": "danger"})
    elif med_att > 0:
        threat_indicators.append({"label": "Archive Attachment", "level": "warning"})
    if "fail" in dmarc_status:
        threat_indicators.append({"label": "DMARC Failed", "level": "danger"})
    if "fail" in dkim_status:
        threat_indicators.append({"label": "DKIM Signature Invalid", "level": "warning"})
    if not threat_indicators:
        threat_indicators.append({"label": "Headers Clean", "level": "success"})
        threat_indicators.append({"label": "No Malicious URL", "level": "success"})

    return {
        "prediction": prediction,
        "confidence": confidence,
        "phishing_probability": int(phishing_prob * 100),
        "risk_score": risk_score,
        "threat": threat,
        "threat_level": threat,
        "risk_reasons": risk_reasons,
        "threat_indicators": threat_indicators,
        "urls": url_results,
        "ips": ips,
        "forensics": forensic_data,
        "ip_results": ip_results or [],
        "iocs": ioc_data,
        "attachments": attachment_data,
        "timeline": timeline,
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges
        }
    }


def process_email_source(raw_bytes=None, text_content=None):
    """Helper to process email bytes or text and perform full forensic analysis."""
    message = None
    email_text = ""
    forensic_data = None
    header_ips = []
    ip_results = []

    if raw_bytes:
        try:
            message = parse_email(raw_bytes)
        except Exception as e:
            print(f"Error parsing raw bytes: {e}")

        if message is not None:
            try:
                email_text = get_email_body(message)
            except Exception:
                email_text = ""
            
            if not email_text.strip():
                email_text = raw_bytes.decode("utf-8", errors="replace")

            try:
                forensic_data = analyze_headers(message)
            except Exception as e:
                print(f"Error in header analysis: {e}")

            try:
                header_ips = extract_header_ips(message)
            except Exception as e:
                print(f"Error extracting header IPs: {e}")
    elif text_content:
        email_text = text_content
        try:
            message = parse_email(text_content.encode("utf-8", errors="ignore"))
            forensic_data = analyze_headers(message)
            header_ips = extract_header_ips(message)
            body = get_email_body(message)
            if body and body.strip():
                email_text = body
        except Exception:
            pass

    # Geolocation for extracted IPs
    for ip in header_ips:
        try:
            loc = get_ip_location(ip)
            ip_results.append(loc)
        except Exception:
            ip_results.append({
                "ip": ip, "type": "Unknown", "country": "Unavailable",
                "city": "Unavailable", "region": "Unavailable",
                "organization": "Unavailable", "latitude": None, "longitude": None
            })

    if not email_text.strip():
        raise ValueError("No readable content could be extracted from the email.")

    # Run analysis
    result = analyze_email(
        email_text=email_text,
        forensic_data=forensic_data,
        ip_results=ip_results,
        message=message
    )

    # Determine sender, receiver, subject
    f_info = result.get("forensics", {})
    sender = f_info.get("from", "")
    receiver = f_info.get("to", "")
    if not receiver and message is not None:
        try:
            receiver = message.get("To", "")
        except Exception:
            pass
    subject = f_info.get("subject", "")

    # Save to Supabase / SQLite
    case_id = save_investigation(
        result=result,
        sender=sender,
        receiver=receiver,
        subject=subject
    )
    result["case_id"] = case_id
    result["sender"] = sender
    result["receiver"] = receiver
    result["subject"] = subject

    return result, case_id


# ============================================================
# WEB ROUTES
# ============================================================

@app.route("/", methods=["GET", "POST"])
@app.route("/api/index", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()
        uploaded_file = request.files.get("email_file")

        try:
            if uploaded_file and uploaded_file.filename:
                filename = uploaded_file.filename.strip()
                if not filename.lower().endswith(".eml"):
                    error = "Only .eml files are supported for file upload."
                else:
                    raw_bytes = uploaded_file.read()
                    if not raw_bytes.strip():
                        error = "The uploaded file is empty."
                    else:
                        result, case_id = process_email_source(raw_bytes=raw_bytes)
                        session["analysis_result"] = result
                        session["case_id"] = case_id
            elif email_text:
                result, case_id = process_email_source(text_content=email_text)
                session["analysis_result"] = result
                session["case_id"] = case_id
            else:
                error = "Please upload an .eml file or paste email content."
        except Exception as e:
            error = f"Analysis failed: {str(e)}"

    stats = get_investigation_stats()
    presets = get_all_presets()
    supabase_active = is_supabase_configured()

    return render_template(
        "index.html",
        result=result,
        error=error,
        stats=stats,
        presets=presets,
        supabase_active=supabase_active,
        model_metrics=model_metrics
    )


# ============================================================
# REST API ENDPOINTS (FOR VERCEL & FRONTEND INTEGRATIONS)
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze an email from uploaded file, JSON payload, or form-data."""
    try:
        raw_bytes = None
        email_text = None

        if "email_file" in request.files:
            file = request.files["email_file"]
            if file and file.filename:
                raw_bytes = file.read()
        elif request.is_json:
            data = request.get_json()
            email_text = data.get("email_text") or data.get("text")
        elif request.form.get("email_text"):
            email_text = request.form.get("email_text")

        if not raw_bytes and not email_text:
            return jsonify({
                "success": False,
                "error": "No email content provided. Send 'email_file' or 'email_text'."
            }), 400

        result, case_id = process_email_source(raw_bytes=raw_bytes, text_content=email_text)
        try:
            session["analysis_result"] = result
            session["case_id"] = case_id
        except Exception:
            pass

        return jsonify({
            "success": True,
            "case_id": case_id,
            "data": result
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/api/presets", methods=["GET"])
def api_presets():
    """Return all pre-packaged demonstration cases."""
    return jsonify({
        "success": True,
        "presets": get_all_presets()
    })


@app.route("/api/preset/<preset_id>", methods=["POST", "GET"])
def api_run_preset(preset_id):
    """Run analysis on a sample preset directly."""
    preset = get_preset(preset_id)
    if not preset:
        return jsonify({"success": False, "error": f"Preset '{preset_id}' not found."}), 404

    try:
        result, case_id = process_email_source(text_content=preset["raw_text"])
        try:
            session["analysis_result"] = result
            session["case_id"] = case_id
        except Exception:
            pass
        return jsonify({
            "success": True,
            "case_id": case_id,
            "preset_id": preset_id,
            "data": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return live aggregate statistics."""
    stats = get_investigation_stats()
    stats["supabase_active"] = is_supabase_configured()
    return jsonify({
        "success": True,
        "stats": stats
    })


@app.route("/api/history", methods=["GET"])
def api_history():
    """Return past investigation cases."""
    investigations = get_all_investigations()
    return jsonify({
        "success": True,
        "count": len(investigations),
        "database": "supabase" if is_supabase_configured() else "sqlite",
        "investigations": investigations
    })


@app.route("/api/case/<case_id>", methods=["GET"])
def api_case_details(case_id):
    """Return complete details for a single investigation case."""
    investigation = get_investigation(case_id)
    if not investigation:
        return jsonify({"success": False, "error": f"Case {case_id} not found."}), 404
    return jsonify({
        "success": True,
        "case": investigation
    })


@app.route("/api/supabase-status", methods=["GET"])
def api_supabase_status():
    """Check Supabase configuration and test connection."""
    configured = is_supabase_configured()
    url, _ = get_supabase_credentials()
    if not configured:
        return jsonify({
            "configured": False,
            "connected": False,
            "message": "Supabase credentials are not set. Platform is operating in local SQLite mode."
        })

    connected, msg = test_supabase_connection()
    return jsonify({
        "configured": True,
        "connected": connected,
        "supabase_url": url,
        "message": msg
    })


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    """Update Supabase credentials at runtime."""
    data = request.get_json() or {}
    url = data.get("supabase_url", "").strip()
    key = data.get("supabase_key", "").strip()

    if url:
        os.environ["SUPABASE_URL"] = url
    if key:
        os.environ["SUPABASE_KEY"] = key

    # Write to .env file for persistence across restarts
    try:
        env_lines = []
        if os.path.exists(".env"):
            with open(".env", "r", encoding="utf-8") as f:
                env_lines = f.readlines()
        
        new_lines = []
        seen_url = False
        seen_key = False
        for line in env_lines:
            if line.startswith("SUPABASE_URL="):
                new_lines.append(f"SUPABASE_URL={url}\n")
                seen_url = True
            elif line.startswith("SUPABASE_KEY="):
                new_lines.append(f"SUPABASE_KEY={key}\n")
                seen_key = True
            else:
                new_lines.append(line)
        if not seen_url and url:
            new_lines.append(f"SUPABASE_URL={url}\n")
        if not seen_key and key:
            new_lines.append(f"SUPABASE_KEY={key}\n")

        with open(".env", "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception as e:
        print(f"Could not write to .env: {e}")

    connected, msg = test_supabase_connection()
    return jsonify({
        "success": connected,
        "message": msg,
        "configured": is_supabase_configured()
    })


@app.route("/api/sync-supabase", methods=["POST"])
def api_sync_supabase():
    """Migrate all local SQLite cases into Supabase."""
    synced, err = sync_sqlite_to_supabase()
    if err:
        return jsonify({"success": False, "error": err}), 400
    return jsonify({
        "success": True,
        "synced_count": synced,
        "message": f"Successfully synced {synced} case(s) to Supabase PostgreSQL database!"
    })


@app.route("/api/export-report", methods=["POST", "GET"])
def api_export_report():
    """Generate and return the PDF forensic report."""
    case_id = request.args.get("case_id") or (request.json.get("case_id") if request.is_json else None)
    result = None

    if case_id:
        case = get_investigation(case_id)
        if case:
            result = {
                "prediction": case.get("prediction"),
                "confidence": case.get("confidence"),
                "risk_score": case.get("risk_score"),
                "threat": case.get("threat_level"),
                "risk_reasons": case.get("risk_reasons", []),
                "forensics": case.get("forensic_data", {}),
                "iocs": case.get("ioc_data", {}),
                "attachments": case.get("attachment_data", {}),
                "timeline": case.get("timeline_data", []),
                "urls": [],
                "ip_results": []
            }
    
    if not result:
        try:
            result = session.get("analysis_result")
        except Exception:
            result = None

    if not result:
        try:
            all_inv = get_all_investigations()
            if all_inv:
                latest = get_investigation(all_inv[0]["case_id"])
                if latest:
                    result = {
                        "prediction": latest.get("prediction"),
                        "confidence": latest.get("confidence"),
                        "risk_score": latest.get("risk_score"),
                        "threat": latest.get("threat_level"),
                        "risk_reasons": latest.get("risk_reasons", []),
                        "forensics": latest.get("forensic_data", {}),
                        "iocs": latest.get("ioc_data", {}),
                        "attachments": latest.get("attachment_data", {}),
                        "timeline": latest.get("timeline_data", []),
                        "case_id": latest.get("case_id"),
                        "urls": [],
                        "ip_results": []
                    }
        except Exception:
            pass

    if not result:
        return jsonify({"error": "No analysis result found. Please analyze an email first."}), 400

    try:
        reports_dir = os.path.join(tempfile.gettempdir(), "reports") if os.environ.get("VERCEL") else "reports"
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, "email_forensic_report.pdf")
        generate_pdf_report(result, pdf_path)

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"forensic_report_{result.get('case_id', 'latest')}.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF report: {str(e)}"}), 500


# ============================================================
# LEGACY TEMPLATE ROUTES
# ============================================================

@app.route("/history", methods=["GET"])
def investigation_history():
    try:
        investigations = get_all_investigations()
        return render_template("history.html", investigations=investigations)
    except Exception as e:
        return f"Unable to load investigation history: {e}", 500


@app.route("/case/<case_id>", methods=["GET"])
def investigation_details(case_id):
    try:
        investigation = get_investigation(case_id)
        if not investigation:
            return "Investigation case not found.", 404
        return render_template("case_details.html", investigation=investigation)
    except Exception as e:
        return f"Unable to load investigation details: {e}", 500


@app.route("/generate-report", methods=["GET"])
def generate_report():
    result = session.get("analysis_result")
    if not result:
        return "No analysis result available. Please analyze an email first."
    try:
        reports_dir = os.path.join(tempfile.gettempdir(), "reports") if os.environ.get("VERCEL") else "reports"
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, "email_forensic_report.pdf")
        generate_pdf_report(result, pdf_path)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name="email_forensic_report.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return f"PDF report generation error: {e}", 500


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    from src.database import initialize_database
    initialize_database()
    print("Database initialized successfully!")
    print(f"Supabase Status: {'Active' if is_supabase_configured() else 'Local SQLite Mode'}")
    app.run(debug=True, port=5000)
