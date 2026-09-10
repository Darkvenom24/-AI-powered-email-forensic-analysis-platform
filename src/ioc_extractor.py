import re
from urllib.parse import urlparse


def extract_urls(text):
    if not text:
        return []
    urls = re.findall(r'https?://[^\s<>"\']+', text, flags=re.IGNORECASE)
    cleaned = [url.rstrip('.,);]}>') for url in urls]
    return list(dict.fromkeys(cleaned))


def extract_ips(text):
    if not text:
        return []
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = []
    for ip in re.findall(pattern, text):
        parts = ip.split('.')
        if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
            ips.append(ip)
    return list(dict.fromkeys(ips))


def extract_emails(text):
    if not text:
        return []
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    return list(dict.fromkeys(re.findall(pattern, text)))


def extract_domains(text):
    domains = []
    for url in extract_urls(text):
        try:
            netloc = urlparse(url).netloc.lower()
            if '@' in netloc:
                netloc = netloc.rsplit('@', 1)[-1]
            domain = netloc.split(':', 1)[0]
            if domain:
                domains.append(domain)
        except Exception:
            pass
    return list(dict.fromkeys(domains))


def extract_iocs(text):
    urls = extract_urls(text)
    ips = extract_ips(text)
    emails = extract_emails(text)
    domains = extract_domains(text)
    return {
        'urls': urls,
        'ips': ips,
        'emails': emails,
        'domains': domains,
        'url_count': len(urls),
        'ip_count': len(ips),
        'email_count': len(emails),
        'domain_count': len(domains),
    }


if __name__ == '__main__':
    sample = '''From: security@example.com\nTo: victim@gmail.com\nVisit http://192.168.1.50/login/verify or https://secure-login-example.com/account/update'''
    print(extract_iocs(sample))
