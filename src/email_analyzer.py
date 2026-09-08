def analyze_email(email_text):
    """
    Basic email threat analyzer.
    """

    suspicious_words = [
        "urgent",
        "verify your account",
        "click here",
        "password",
        "winner",
        "bank",
        "login",
        "suspended",
        "confirm your account"
    ]

    email_lower = email_text.lower()

    detected = []

    for word in suspicious_words:
        if word in email_lower:
            detected.append(word)

    if len(detected) >= 3:
        risk = "HIGH"
    elif len(detected) >= 1:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "suspicious_keywords": detected
    }


if __name__ == "__main__":

    test_email = """
    URGENT! Your bank account has been suspended.
    Click here to verify your password and login immediately.
    """

    result = analyze_email(test_email)

    print("Email Threat Analysis")
    print("---------------------")
    print("Risk Level:", result["risk"])
    print("Suspicious Keywords:", result["suspicious_keywords"])