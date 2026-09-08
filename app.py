from flask import Flask, render_template, request, session, send_file
import joblib
import re
import os

from src.url_analyzer import extract_urls, analyze_url
from src.forensics import (
    parse_email,
    get_email_body,
    analyze_headers,
    extract_header_ips
)
from src.geolocation import get_ip_location
from src.pdf_report import generate_pdf_report


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.secret_key = "ai-email-threat-detector-secret-key"

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


# ============================================================
# LOAD ML MODEL
# ============================================================

model = joblib.load(
    "models/email_threat_model.pkl"
)


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
    ip_results=None
):

    # --------------------------------------------------------
    # 1. ML THREAT DETECTION
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # 5.1 ML THREAT CLASS
    # --------------------------------------------------------

    if prediction_lower == "phishing":

        risk_score += 60

        risk_reasons.append(
            "AI model classified the email as PHISHING"
        )

    elif prediction_lower == "spam":

        risk_score += 30

        risk_reasons.append(
            "AI model classified the email as SPAM"
        )

    else:

        risk_reasons.append(
            "AI model classified the email as SAFE"
        )


    # --------------------------------------------------------
    # 5.2 ML CONFIDENCE
    # --------------------------------------------------------

    if confidence >= 80:

        risk_score += 15

        risk_reasons.append(
            "High ML confidence"
        )

    elif confidence >= 60:

        risk_score += 10

        risk_reasons.append(
            "Moderate ML confidence"
        )

    else:

        risk_reasons.append(
            "Low ML confidence"
        )


    # --------------------------------------------------------
    # 5.3 URL ANALYSIS
    # --------------------------------------------------------

    for url_data in url_results:

        url_risk = url_data.get(
            "risk_score",
            0
        )

        risk_score += min(
            int(url_risk * 0.4),
            15
        )

        if url_data.get(
            "suspicious",
            False
        ):

            risk_score += 15

            risk_reasons.append(
                "Suspicious URL detected"
            )

        indicators = url_data.get(
            "indicators",
            []
        )

        if indicators:

            risk_reasons.append(
                f"Suspicious URL indicators detected: "
                f"{len(indicators)}"
            )


    # --------------------------------------------------------
    # 5.4 FORENSIC ANALYSIS
    # --------------------------------------------------------

    forensic_indicators = []

    if forensic_data:

        forensic_indicators = forensic_data.get(
            "indicators",
            []
        )


    forensic_score = min(
        len(forensic_indicators) * 5,
        15
    )

    risk_score += forensic_score


    if forensic_indicators:

        risk_reasons.append(
            f"Email forensic indicators detected: "
            f"{len(forensic_indicators)}"
        )


    # --------------------------------------------------------
    # 5.5 IP ANALYSIS
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # 5.6 FINAL SCORE
    # --------------------------------------------------------

    risk_score = min(
        int(risk_score),
        100
    )


    # --------------------------------------------------------
    # 5.7 FINAL THREAT LEVEL
    # --------------------------------------------------------

    if risk_score >= 70:

        threat = "HIGH RISK"

    elif risk_score >= 40:

        threat = "MEDIUM RISK"

    else:

        threat = "LOW RISK"


    # --------------------------------------------------------
    # 5.8 REMOVE DUPLICATE REASONS
    # --------------------------------------------------------

    risk_reasons = list(
        dict.fromkeys(
            risk_reasons
        )
    )


    # --------------------------------------------------------
    # 6. RETURN RESULT
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
        )


        if pasted_text.strip():

            email_text = pasted_text


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


            # Check extension

            if not uploaded_file.filename.lower().endswith(
                ".eml"
            ):

                error = (
                    "Only .eml files are allowed."
                )

            else:

                try:

                    # --------------------------------
                    # Read file
                    # --------------------------------

                    raw_bytes = uploaded_file.read()


                    # --------------------------------
                    # Empty file check
                    # --------------------------------

                    if not raw_bytes:

                        error = (
                            "Uploaded file is empty."
                        )

                    else:

                        # --------------------------------
                        # Parse email
                        # --------------------------------

                        message = parse_email(
                            raw_bytes
                        )


                        # --------------------------------
                        # Extract body
                        # --------------------------------

                        body = get_email_body(
                            message
                        )


                        # --------------------------------
                        # Fallback to complete email
                        # --------------------------------

                        if not body.strip():

                            body = raw_bytes.decode(
                                "utf-8",
                                errors="replace"
                            )


                        # --------------------------------
                        # Forensic analysis
                        # --------------------------------

                        forensic_data = analyze_headers(
                            message
                        )


                        # --------------------------------
                        # Extract header IPs
                        # --------------------------------

                        header_ips = extract_header_ips(
                            message
                        )


                        # --------------------------------
                        # IP geolocation
                        # --------------------------------

                        ip_results = []


                        for ip in header_ips:

                            location = get_ip_location(
                                ip
                            )

                            ip_results.append(
                                location
                            )


                        # --------------------------------
                        # Complete analysis
                        # --------------------------------

                        result = analyze_email(
                            body,
                            forensic_data,
                            ip_results
                        )


                except Exception as e:

                    error = (
                        f"Email analysis failed: {e}"
                    )


        # ----------------------------------------------------
        # 3. ANALYZE PASTED EMAIL
        # ----------------------------------------------------

        elif email_text.strip() and not error:

            result = analyze_email(
                email_text
            )


        # ====================================================
        # STORE RESULT FOR PDF
        # ====================================================

        if result and not error:

            session[
                "analysis_result"
            ] = result


    # ========================================================
    # RENDER DASHBOARD
    # ========================================================

    return render_template(
        "index.html",
        result=result,
        error=error
    )


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

        return (
            f"PDF report generation failed: {e}"
        )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )