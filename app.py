from flask import Flask, render_template, request, session, send_file
import joblib
import re
import os
import json

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
    get_investigation_stats
)

# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

# ============================================================
# SECURITY CONFIGURATION
# ============================================================

# Keep the secret key outside source code in production.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret-key"
)

if app.secret_key == "dev-only-change-this-secret-key":
    print(
        "WARNING: FLASK_SECRET_KEY is not set. "
        "Using development secret key."
    )

# Maximum HTTP request size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# ============================================================
# LOAD ML MODEL
# ============================================================

MODEL_PATH = "models/email_threat_model.pkl"

try:
    model = joblib.load(MODEL_PATH)
    print("ML model loaded successfully!")
except Exception as e:
    model = None
    print(f"WARNING: Failed to load ML model: {e}")

# ============================================================
# LOAD ML MODEL PERFORMANCE METRICS
# ============================================================

METRICS_PATH = "data/model_metrics.json"

try:

    with open(
        METRICS_PATH,
        "r",
        encoding="utf-8"
    ) as f:

        model_metrics = json.load(f)

    print("Model metrics loaded successfully!")

except Exception as e:

    print(
        f"Failed to load model metrics: {e}"
    )

    model_metrics = {}

# ============================================================
# SECURITY / ERROR HANDLING HELPERS
# ============================================================

MAX_EMAIL_FILE_SIZE = 5 * 1024 * 1024

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

# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ips(text):

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return re.findall(
        pattern,
        text
    )

# ============================================================
# EMAIL ANALYSIS
# ============================================================

def analyze_email(
    email_text,
    forensic_data=None,
    ip_results=None,
    message=None
):

    # --------------------------------------------------------
    # 1. ML THREAT DETECTION
    # --------------------------------------------------------

    if model is None:
        raise RuntimeError(
            "ML model is unavailable. Please check the model file."
        )

    if not isinstance(email_text, str) or not email_text.strip():
        raise ValueError("Email content cannot be empty.")

    prediction = model.predict(
        [email_text]
    )[0]

    probabilities = model.predict_proba(
        [email_text]
    )[0]

    confidence = max(
        probabilities
    ) * 100

    # --------------------------------------------------------
    # 2. URL ANALYSIS
    # --------------------------------------------------------

    urls = extract_urls(
        email_text
    )

    url_results = []

    for url in urls:

        url_result = analyze_url(
            url
        )

        url_results.append(
            url_result
        )

    # --------------------------------------------------------
    # 3. IP EXTRACTION
    # --------------------------------------------------------

    ips = extract_ips(
        email_text
    )

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

    # --------------------------------------------------------
    # 4. FORENSICS
    # --------------------------------------------------------

    if forensic_data is None:

        try:

            message = parse_email(
                email_text.encode(
                    "utf-8",
                    errors="ignore"
                )
            )

            forensic_data = analyze_headers(
                message
            )

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
    # 5. RISK ENGINE
    # --------------------------------------------------------

    risk_score = 0
    risk_reasons = []

    prediction_lower = prediction.lower()

    # Normalize authentication results.
    spf_status = str(
        forensic_data.get("spf", "Not Found")
        if forensic_data else "Not Found"
    ).lower()

    dkim_status = str(
        forensic_data.get("dkim", "Not Found")
        if forensic_data else "Not Found"
    ).lower()

    dmarc_status = str(
        forensic_data.get("dmarc", "Not Found")
        if forensic_data else "Not Found"
    ).lower()

    # ========================================================
    # 5.1 ML THREAT CLASS
    # ========================================================

    if prediction_lower == "phishing":

        risk_score += 55

        risk_reasons.append(
            "AI model classified the email as PHISHING"
        )

    elif prediction_lower == "spam":

        risk_score += 25

        risk_reasons.append(
            "AI model classified the email as SPAM"
        )

    else:

        risk_reasons.append(
            "AI model classified the email as SAFE"
        )

    # ========================================================
    # 5.2 ML CONFIDENCE
    # ========================================================

    if confidence >= 90:

        risk_score += 15

        risk_reasons.append(
            "Very high ML confidence"
        )

    elif confidence >= 80:

        risk_score += 12

        risk_reasons.append(
            "High ML confidence"
        )

    elif confidence >= 60:

        risk_score += 7

        risk_reasons.append(
            "Moderate ML confidence"
        )

    else:

        risk_reasons.append(
            "Low ML confidence"
        )

    # ========================================================
    # 5.3 URL ANALYSIS
    # ========================================================

    suspicious_url_count = 0
    severe_url_count = 0

    for url_data in url_results:

        url_risk = int(
            url_data.get(
                "risk_score",
                0
            ) or 0
        )

        indicators = url_data.get(
            "indicators",
            []
        ) or []

        # Base URL contribution.
        risk_score += min(
            int(url_risk * 0.30),
            12
        )

        if url_data.get(
            "suspicious",
            False
        ):

            suspicious_url_count += 1

            risk_score += 10

            risk_reasons.append(
                "Suspicious URL detected"
            )

        if url_risk >= 50:

            severe_url_count += 1

            risk_score += 8

            risk_reasons.append(
                "High-risk URL detected"
            )

        if indicators:

            risk_reasons.append(
                f"Suspicious URL indicators detected: "
                f"{len(indicators)}"
            )

    # ========================================================
    # 5.4 PHISHING + URL CORRELATION
    # ========================================================

    # A phishing classification combined with a suspicious URL
    # is stronger evidence than either signal alone.
    if (
        prediction_lower == "phishing"
        and suspicious_url_count > 0
    ):

        risk_score += 10

        risk_reasons.append(
            "Phishing classification is reinforced by a suspicious URL"
        )

    # ========================================================
    # 5.5 EMAIL AUTHENTICATION
    # ========================================================

    auth_failures = 0

    for name, status in (
        ("SPF", spf_status),
        ("DKIM", dkim_status),
        ("DMARC", dmarc_status),
    ):

        if status == "fail":

            auth_failures += 1

            risk_score += 7

            risk_reasons.append(
                f"{name} authentication failed"
            )

    # Multiple authentication failures are stronger evidence.
    if auth_failures >= 2:

        risk_score += 5

        risk_reasons.append(
            "Multiple email authentication failures detected"
        )

    # ========================================================
    # 5.6 FORENSIC ANALYSIS
    # ========================================================

    forensic_indicators = []

    if forensic_data:

        forensic_indicators = forensic_data.get(
            "indicators",
            []
        ) or []

    forensic_score = min(
        len(forensic_indicators) * 4,
        12
    )

    risk_score += forensic_score

    if forensic_indicators:

        risk_reasons.append(
            f"Email forensic indicators detected: "
            f"{len(forensic_indicators)}"
        )

    # Detect a From / Reply-To mismatch from the forensic indicators.
    mismatch_detected = any(
        "reply-to" in str(indicator).lower()
        and (
            "mismatch" in str(indicator).lower()
            or "different" in str(indicator).lower()
        )
        for indicator in forensic_indicators
    )

    if mismatch_detected:

        risk_score += 8

        risk_reasons.append(
            "From and Reply-To domains do not match"
        )

    # ========================================================
    # 5.7 ATTACHMENT RISK
    # ========================================================

    high_attachment_count = int(
        attachment_data.get("high_risk_count", 0) or 0
    )
    medium_attachment_count = int(
        attachment_data.get("medium_risk_count", 0) or 0
    )

    if high_attachment_count > 0:
        risk_score += min(high_attachment_count * 20, 30)
        risk_reasons.append(
            f"{high_attachment_count} high-risk attachment(s) detected"
        )
    elif medium_attachment_count > 0:
        risk_score += min(medium_attachment_count * 10, 15)
        risk_reasons.append(
            f"{medium_attachment_count} medium-risk attachment(s) detected"
        )

    # ========================================================
    # 5.8 IP ANALYSIS
    # ========================================================

    public_ip_count = 0

    if ip_results:

        for ip_data in ip_results:

            if ip_data.get(
                "type"
            ) == "Public IP":

                public_ip_count += 1

    if public_ip_count > 0:

        risk_score += min(
            public_ip_count * 2,
            6
        )

        risk_reasons.append(
            f"{public_ip_count} public IP address(es) found"
        )

    # ========================================================
    # 5.9 SAFE EMAIL FALSE-POSITIVE CONTROL
    # ========================================================

    # A high-confidence SAFE prediction should not become high risk
    # from weak secondary signals alone.
    if (
        prediction_lower == "safe"
        and confidence >= 85
        and suspicious_url_count == 0
        and auth_failures == 0
        and not forensic_indicators
    ):

        risk_score = min(
            risk_score,
            15
        )

        risk_reasons.append(
            "High-confidence safe email with no strong secondary indicators"
        )

    # ========================================================
    # 5.10 FINAL SCORE
    # ========================================================

    risk_score = min(
        int(risk_score),
        100
    )

    # ========================================================
    # 5.11 FINAL THREAT LEVEL
    # ========================================================

    if risk_score >= 70:

        threat = "HIGH RISK"

    elif risk_score >= 40:

        threat = "MEDIUM RISK"

    else:

        threat = "LOW RISK"

    # ========================================================
    # 5.12 REMOVE DUPLICATE REASONS
    # ========================================================

    risk_reasons = list(
        dict.fromkeys(
            risk_reasons
        )
    )

    # --------------------------------------------------------
    # 6. FORENSIC TIMELINE
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # 7. RETURN RESULT
    # --------------------------------------------------------

    return {

        "prediction":
            prediction.upper(),

        "confidence":
            round(
                confidence,
                2
            ),

        "risk_score":
            risk_score,

        "threat":
            threat,

        "risk_reasons":
            risk_reasons,

        "urls":
            url_results,

        "ips":
            ips,

        "forensics":
            forensic_data,

        "ip_results":
            ip_results or []
,

        "iocs":
            ioc_data,

        "attachments":
            attachment_data,

        "timeline":
            timeline
    }

# ============================================================
# HOME PAGE
# ============================================================

@app.route(
    "/",
    methods=[
        "GET",
        "POST"
    ]
)

def index():

    result = None

    error = None

    # ========================================================
    # POST REQUEST
    # ========================================================

    if request.method == "POST":

        email_text = ""

        # ----------------------------------------------------
        # 1. PASTED EMAIL
        # ----------------------------------------------------

        pasted_text = request.form.get(
            "email_text",
            ""
        ).strip()

        if pasted_text:
            email_text = pasted_text
        else:
            email_text = ""

        # ----------------------------------------------------
        # 2. .EML FILE UPLOAD
        # ----------------------------------------------------

        uploaded_file = request.files.get(
            "email_file"
        )

        if (
            uploaded_file
            and uploaded_file.filename
        ):

            # Check filename
            filename = uploaded_file.filename.strip()

            if not filename:

                error = "Please select an .eml file."

            elif not filename.lower().endswith(".eml"):

                error = "Only .eml files are allowed."

            else:

                try:

                    # --------------------------------
                    # Read file
                    # --------------------------------

                    raw_bytes = uploaded_file.read()

                    # --------------------------------
                    # File size check
                    # --------------------------------

                    if len(raw_bytes) > MAX_EMAIL_FILE_SIZE:

                        error = (
                            "Uploaded file is too large. "
                            "Maximum allowed size is 5 MB."
                        )

                    # --------------------------------
                    # Empty file check
                    # --------------------------------

                    elif not raw_bytes.strip():

                        error = "Uploaded file is empty."

                    else:

                        # --------------------------------
                        # Parse email safely
                        # --------------------------------

                        try:
                            message = parse_email(
                                raw_bytes
                            )
                        except Exception as parse_error:
                            print(
                                f"Email parsing warning: {parse_error}"
                            )
                            message = None

                        if message is None:

                            error = (
                                "Invalid or malformed .eml file. "
                                "Unable to parse the email."
                            )

                        elif not is_valid_eml(
                            message,
                            raw_bytes
                        ):

                            error = (
                                "Invalid .eml file. "
                                "No valid email headers were found."
                            )

                        else:

                            # --------------------------------
                            # Extract body
                            # --------------------------------

                            try:
                                body = get_email_body(
                                    message
                                )
                            except Exception as body_error:
                                print(
                                    f"Email body extraction warning: "
                                    f"{body_error}"
                                )
                                body = ""

                            # --------------------------------
                            # Fallback to complete email
                            # --------------------------------

                            if not body.strip():

                                body = raw_bytes.decode(
                                    "utf-8",
                                    errors="replace"
                                )

                            if not body.strip():

                                error = (
                                    "The email does not contain readable content."
                                )

                            else:

                                # --------------------------------
                                # Forensic analysis
                                # --------------------------------

                                try:
                                    forensic_data = analyze_headers(
                                        message
                                    )
                                except Exception as forensic_error:

                                    print(
                                        f"Forensic analysis warning: "
                                        f"{forensic_error}"
                                    )

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
                                        "indicators": [
                                            "Email forensic analysis could not be completed."
                                        ]
                                    }

                                # --------------------------------
                                # Extract header IPs
                                # --------------------------------

                                try:
                                    header_ips = extract_header_ips(
                                        message
                                    )
                                except Exception as ip_error:

                                    print(
                                        f"Header IP extraction warning: "
                                        f"{ip_error}"
                                    )

                                    header_ips = []

                                # --------------------------------
                                # IP geolocation
                                # --------------------------------

                                ip_results = []

                                for ip in header_ips:

                                    try:

                                        location = get_ip_location(
                                            ip
                                        )

                                        if not isinstance(
                                            location,
                                            dict
                                        ):
                                            location = {
                                                "ip": ip,
                                                "type": "Unknown",
                                                "country": "Unavailable",
                                                "city": "Unavailable",
                                                "region": "Unavailable",
                                                "organization": "Unavailable",
                                                "latitude": None,
                                                "longitude": None,
                                            }

                                    except Exception as geo_error:

                                        print(
                                            f"Geolocation warning for {ip}: "
                                            f"{geo_error}"
                                        )

                                        location = {
                                            "ip": ip,
                                            "type": "Unknown",
                                            "country": "Unavailable",
                                            "city": "Unavailable",
                                            "region": "Unavailable",
                                            "organization": "Unavailable",
                                            "latitude": None,
                                            "longitude": None,
                                        }

                                    ip_results.append(
                                        location
                                    )

                                # --------------------------------
                                # Complete analysis
                                # --------------------------------

                                try:

                                    result = analyze_email(
                                        body,
                                        forensic_data,
                                        ip_results,
                                        message
                                    )

                                except Exception as analysis_error:

                                    print(
                                        f"Email analysis warning: "
                                        f"{analysis_error}"
                                    )

                                    error = (
                                        "Email analysis failed. "
                                        "Please check the email and try again."
                                    )

                except Exception as e:

                    print(
                        f"Email upload processing error: {e}"
                    )

                    error = (
                        "Unable to process the uploaded email. "
                        "Please check the file and try again."
                    )

        # ----------------------------------------------------
        # 3. ANALYZE PASTED EMAIL
        # ----------------------------------------------------

        elif email_text.strip() and not error:

            try:

                pasted_message = None
                try:
                    pasted_message = parse_email(
                        email_text.encode("utf-8", errors="ignore")
                    )
                except Exception as parse_error:
                    print(f"Pasted email parse warning: {parse_error}")

                result = analyze_email(
                    email_text,
                    message=pasted_message
                )

            except Exception as e:

                print(
                    f"Pasted email analysis error: {e}"
                )

                error = (
                    "Email analysis failed. "
                    "Please check the email content and try again."
                )

        # ----------------------------------------------------
        # 4. EMPTY INPUT VALIDATION
        # ----------------------------------------------------

        elif not email_text.strip() and not error:

            error = (
                "Please upload an .eml file or paste email content."
            )

        # ====================================================
        # STORE RESULT + SAVE INVESTIGATION
        # ====================================================

        if result and not error:

            # Keep latest result in session for PDF generation.
            session["analysis_result"] = result

            # ------------------------------------------------
            # Save investigation to SQLite database
            # ------------------------------------------------
            try:

                forensic_info = result.get(
                    "forensics",
                    {}
                ) or {}

                sender = forensic_info.get(
                    "from",
                    ""
                )

                receiver = forensic_info.get(
                    "to",
                    ""
                )

                if not receiver and message is not None:
                    try:
                        receiver = message.get("To", "")
                    except Exception:
                        receiver = ""

                subject = forensic_info.get(
                    "subject",
                    ""
                )

                # database.py expects a "threat_level" field.
                # The analysis result uses "threat", so normalize it here.
                result["threat_level"] = result.get(
                    "threat",
                    "UNKNOWN"
                )

                # Normalize threat for SQLite statistics.
                result["threat_level"] = result.get(
                    "threat_level",
                    result.get("threat", "UNKNOWN")
                )

                case_id = save_investigation(
                    result=result,
                    sender=sender,
                    receiver=receiver,
                    subject=subject
                )

                # Store case ID so it can be shown on dashboard
                # and used for follow-up actions.
                session["case_id"] = case_id

                # Make the case ID available to the template.
                result["case_id"] = case_id

                print(
                    f"Investigation saved successfully: {case_id}"
                )

            except Exception as db_error:

                # Database failure should not prevent the user
                # from seeing the email analysis result.
                print(
                    f"Database save warning: {db_error}"
                )

    # ========================================================
    # RENDER DASHBOARD
    # ========================================================

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

@app.route(
    "/history",
    methods=["GET"]
)
def investigation_history():

    try:

        investigations = get_all_investigations()

        return render_template(
            "history.html",
            investigations=investigations
        )

    except Exception as e:

        print(
            f"History loading error: {e}"
        )

        return (
            "Unable to load investigation history."
        ), 500


# ============================================================
# INVESTIGATION DETAILS
# ============================================================

@app.route(
    "/case/<case_id>",
    methods=["GET"]
)
def investigation_details(case_id):

    try:

        investigation = get_investigation(
            case_id
        )

        if not investigation:

            return (
                "Investigation case not found."
            ), 404

        return render_template(
            "case_details.html",
            investigation=investigation
        )

    except Exception as e:

        print(
            f"Case details error: {e}"
        )

        return (
            "Unable to load investigation details."
        ), 500


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@app.route(
    "/generate-report",
    methods=["GET"]
)

def generate_report():

    # --------------------------------------------------------
    # Get latest analysis result
    # --------------------------------------------------------

    result = session.get(
        "analysis_result"
    )

    if not result:

        return (
            "No analysis result available. "
            "Please analyze an email first."
        )

    try:

        # ----------------------------------------------------
        # Create reports folder
        # ----------------------------------------------------

        reports_folder = "reports"

        os.makedirs(
            reports_folder,
            exist_ok=True
        )

        # ----------------------------------------------------
        # PDF filename
        # ----------------------------------------------------

        pdf_path = os.path.join(
            reports_folder,
            "email_forensic_report.pdf"
        )

        # ----------------------------------------------------
        # Generate PDF
        # ----------------------------------------------------

        generate_pdf_report(
            result,
            pdf_path
        )

        # ----------------------------------------------------
        # Send PDF
        # ----------------------------------------------------

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name="email_forensic_report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:

        print(
            f"PDF report generation error: {e}"
        )

        return (
            "PDF report generation failed. "
            "Please try again after analyzing the email."
        ), 500

# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    # Initialize SQLite database before starting Flask.
    try:
        from src.database import initialize_database

        initialize_database()

        print(
            "Investigation database initialized successfully!"
        )

    except Exception as db_error:

        print(
            f"WARNING: Database initialization failed: {db_error}"
        )

    app.run(
        debug=False
    )
