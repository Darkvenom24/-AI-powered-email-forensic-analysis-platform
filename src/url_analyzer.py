import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "bank",
    "confirm",
    "signin",
    "payment",
    "wallet",
    "credential"
]

SHORTENED_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "soo.gd",
    "s.id"
}


def extract_urls(text):
    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(pattern, text)
    return list(dict.fromkeys(urls))


def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def is_shortened_domain(domain):
    domain = domain.lower()
    for s_dom in SHORTENED_DOMAINS:
        if domain == s_dom or domain.endswith("." + s_dom):
            return True
    return False


def analyze_url(url, known_threat_urls=None):
    indicators = []
    risk_score = 0

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Remove username/password if present
    if "@" in domain:
        domain = domain.split("@")[-1]

    # Remove port
    domain = domain.split(":")[0]

    # --------------------------------
    # THREAT INTELLIGENCE CHECK
    # --------------------------------
    if known_threat_urls:
        norm_url = url.strip().lower()
        if norm_url in known_threat_urls or norm_url.rstrip("/") in known_threat_urls:
            indicators.append("Known phishing URL match in threat intelligence feed")
            risk_score += 40

    # --------------------------------
    # SHORTENED URL CHECK
    # --------------------------------
    if is_shortened_domain(domain):
        indicators.append("Suspicious shortened URL detected")
        risk_score += 20

    # --------------------------------
    # HTTPS CHECK
    # --------------------------------
    if parsed.scheme != "https":
        indicators.append("URL does not use HTTPS")
        risk_score += 10

    # --------------------------------
    # IP ADDRESS CHECK
    # --------------------------------
    if is_ip_address(domain):
        indicators.append("URL uses an IP address instead of a domain name")
        risk_score += 25

    # --------------------------------
    # LONG URL CHECK
    # --------------------------------
    if len(url) > 100:
        indicators.append("Unusually long URL")
        risk_score += 10

    # --------------------------------
    # @ SYMBOL CHECK
    # --------------------------------
    if "@" in url:
        indicators.append("URL contains @ symbol")
        risk_score += 20

    # --------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            found_keywords.append(keyword)

    if found_keywords:
        indicators.append("Suspicious keywords: " + ", ".join(found_keywords))
        risk_score += min(len(found_keywords) * 5, 20)

    # --------------------------------
    # MANY SUBDOMAINS
    # --------------------------------
    domain_parts = domain.split(".")
    if len(domain_parts) >= 4:
        indicators.append("URL contains multiple subdomains")
        risk_score += 10

    # --------------------------------
    # DASH CHECK
    # --------------------------------
    if domain.count("-") >= 3:
        indicators.append("Domain contains multiple hyphens")
        risk_score += 10

    # --------------------------------
    # FINAL SCORE
    # --------------------------------
    risk_score = min(risk_score, 100)
    suspicious = risk_score >= 20

    return {
        "url": url,
        "domain": domain,
        "suspicious": suspicious,
        "risk_score": risk_score,
        "indicators": indicators
    }