import joblib

from url_analyzer import extract_urls, analyze_url


# Load ML model
model = joblib.load("models/email_threat_model.pkl")


def analyze_email(email_text):

    # -----------------------------
    # 1. ML Threat Prediction
    # -----------------------------

    prediction = model.predict([email_text])[0]

    probabilities = model.predict_proba([email_text])[0]

    confidence = max(probabilities) * 100

    # -----------------------------
    # 2. URL Analysis
    # -----------------------------

    urls = extract_urls(email_text)

    url_results = []

    for url in urls:
        result = analyze_url(url)
        url_results.append(result)

    # -----------------------------
    # 3. Final Risk Score
    # -----------------------------

    risk_score = 0

    if prediction == "phishing":
        risk_score += 60

    elif prediction == "spam":
        risk_score += 30

    # Add URL risk
    for result in url_results:
        risk_score += result["risk_score"] * 0.4

    risk_score = min(round(risk_score), 100)

    # Final classification
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
        "risk_score": risk_score,
        "final_threat": final_threat
    }


if __name__ == "__main__":

    print("=" * 60)
    print("           AI EMAIL THREAT DETECTOR")
    print("=" * 60)

    email_text = input("\nEnter email text:\n")

    result = analyze_email(email_text)

    print("\n" + "=" * 60)
    print("                 ANALYSIS RESULT")
    print("=" * 60)

    print("\nML Prediction :", result["prediction"].upper())
    print("ML Confidence:", f"{result['confidence']:.2f}%")

    print("\nURLs Found:", len(result["urls"]))

    for url_result in result["urls"]:

        print("\nURL:", url_result["url"])
        print("Domain:", url_result["domain"])
        print("URL Risk:", url_result["risk_score"])
        print("Suspicious:", url_result["suspicious"])

        for indicator in url_result["indicators"]:
            print("  -", indicator)

    print("\n--------------------------------------------")
    print("FINAL RISK SCORE:", result["risk_score"], "/ 100")
    print("FINAL THREAT    :", result["final_threat"])
    print("--------------------------------------------")