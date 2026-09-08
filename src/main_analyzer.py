import joblib
import re

from url_analyzer import extract_urls, analyze_url
from geolocation import get_ip_location


# Load trained ML model
model = joblib.load("models/email_threat_model.pkl")


def extract_ips(text):
    """
    Extract IPv4 addresses from text.
    """

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return re.findall(pattern, text)


def analyze_email(email_text):

    # ==========================================
    # 1. ML THREAT DETECTION
    # ==========================================

    prediction = model.predict([email_text])[0]

    probabilities = model.predict_proba([email_text])[0]

    confidence = max(probabilities) * 100


    # ==========================================
    # 2. URL ANALYSIS
    # ==========================================

    urls = extract_urls(email_text)

    url_results = []

    for url in urls:

        result = analyze_url(url)

        url_results.append(result)


    # ==========================================
    # 3. IP EXTRACTION
    # ==========================================

    ips = extract_ips(email_text)

    ip_results = []

    for ip in ips:

        # Ignore private/local IP addresses
        if (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("127.")
        ):
            ip_results.append({
                "ip": ip,
                "type": "Private/Local IP",
                "location": None
            })

        else:

            location = get_ip_location(ip)

            ip_results.append({
                "ip": ip,
                "type": "Public IP",
                "location": location
            })


    # ==========================================
    # 4. RISK SCORE
    # ==========================================

    risk_score = 0


    if prediction == "phishing":

        risk_score += 60

    elif prediction == "spam":

        risk_score += 30


    # URL risk

    for result in url_results:

        risk_score += int(
            result["risk_score"] * 0.4
        )


    # ==========================================
    # 5. FINAL RISK
    # ==========================================

    risk_score = min(
        risk_score,
        100
    )


    if risk_score >= 70:

        final_threat = "HIGH RISK"

    elif risk_score >= 40:

        final_threat = "MEDIUM RISK"

    else:

        final_threat = "LOW RISK"


    return {

        "prediction": prediction,

        "confidence": confidence,

        "urls": url_results,

        "ips": ip_results,

        "risk_score": risk_score,

        "final_threat": final_threat

    }


# ==========================================
# COMMAND LINE APPLICATION
# ==========================================

if __name__ == "__main__":

    print("=" * 65)

    print("          AI EMAIL THREAT DETECTION")

    print("       GEOLOCATION + FORENSICS SYSTEM")

    print("=" * 65)


    print("\nEnter email text.")

    print("Type END on a new line when finished.\n")


    lines = []

    while True:

        line = input()

        if line.strip().upper() == "END":

            break

        lines.append(line)


    email_text = "\n".join(lines)


    result = analyze_email(email_text)


    # ==========================================
    # FINAL REPORT
    # ==========================================

    print("\n")

    print("=" * 65)

    print("                    FINAL REPORT")

    print("=" * 65)


    print(
        "\nML Prediction :",
        result["prediction"].upper()
    )

    print(
        "ML Confidence:",
        f"{result['confidence']:.2f}%"
    )


    print(
        "\nFinal Risk Score:",
        result["risk_score"],
        "/ 100"
    )

    print(
        "Threat Level:",
        result["final_threat"]
    )


    # URL REPORT

    print("\n" + "-" * 65)

    print("URL ANALYSIS")

    print("-" * 65)


    if not result["urls"]:

        print("No URLs detected.")

    else:

        for item in result["urls"]:

            print("\nURL:", item["url"])

            print(
                "Domain:",
                item["domain"]
            )

            print(
                "Risk:",
                item["risk_score"]
            )

            print(
                "Suspicious:",
                item["suspicious"]
            )

            for indicator in item["indicators"]:

                print(
                    "  -",
                    indicator
                )


    # IP REPORT

    print("\n" + "-" * 65)

    print("IP / GEOLOCATION")

    print("-" * 65)


    if not result["ips"]:

        print("No IP addresses detected.")

    else:

        for item in result["ips"]:

            print(
                "\nIP:",
                item["ip"]
            )

            print(
                "Type:",
                item["type"]
            )

            if item["location"]:

                location = item["location"]

                print(
                    "Country:",
                    location.get("country")
                )

                print(
                    "City:",
                    location.get("city")
                )

                print(
                    "Region:",
                    location.get("region")
                )

                print(
                    "Organization:",
                    location.get("organization")
                )

    print("\n" + "=" * 65)
    print("                 ANALYSIS COMPLETE")
    print("=" * 65)
    