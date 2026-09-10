from email.message import Message

HIGH_RISK_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.msi', '.js', '.jse', '.vbs',
    '.vbe', '.ps1', '.jar', '.hta', '.wsf', '.wsh'
}

MEDIUM_RISK_EXTENSIONS = {'.zip', '.rar', '.7z', '.iso'}

SAFE_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv',
    '.jpg', '.jpeg', '.png', '.gif'
}

SUSPICIOUS_FILENAME_KEYWORDS = {
    'invoice', 'payment', 'refund', 'bank', 'password', 'credential', 'verify',
    'account', 'urgent', 'security', 'update'
}


def get_extension(filename):
    filename_lower = filename.lower()
    return '.' + filename_lower.split('.')[-1] if '.' in filename_lower else ''


def has_double_extension(filename):
    parts = filename.lower().split('.')
    if len(parts) < 3:
        return False
    previous_extension = '.' + parts[-2]
    final_extension = '.' + parts[-1]
    normal_extensions = SAFE_EXTENSIONS | MEDIUM_RISK_EXTENSIONS
    return previous_extension in normal_extensions and final_extension in HIGH_RISK_EXTENSIONS


def find_suspicious_keywords(filename):
    filename_lower = filename.lower()
    return sorted(k for k in SUSPICIOUS_FILENAME_KEYWORDS if k in filename_lower)


def analyze_attachment(part: Message):
    filename = part.get_filename() or 'Unnamed Attachment'
    mime_type = part.get_content_type()

    try:
        payload = part.get_payload(decode=True)
        size = 0 if payload is None else len(payload)
    except Exception:
        size = 0

    extension = get_extension(filename)
    risk_score = 0
    indicators = []

    if extension in HIGH_RISK_EXTENSIONS:
        risk_score += 70
        indicators.append('High-risk executable or script file')
    elif extension in MEDIUM_RISK_EXTENSIONS:
        risk_score += 35
        indicators.append('Archive or disk-image attachment')
    elif extension in SAFE_EXTENSIONS:
        risk_score += 5
    else:
        risk_score += 20
        indicators.append('Unknown or uncommon file extension')

    double_extension = has_double_extension(filename)
    if double_extension:
        risk_score += 20
        indicators.append('Double file extension detected')

    suspicious_keywords = find_suspicious_keywords(filename)
    if suspicious_keywords:
        risk_score += min(len(suspicious_keywords) * 5, 15)
        indicators.append('Suspicious filename keywords: ' + ', '.join(suspicious_keywords))

    risk_score = min(risk_score, 100)
    risk = 'HIGH' if risk_score >= 70 else 'MEDIUM' if risk_score >= 40 else 'LOW'

    return {
        'filename': filename,
        'extension': extension,
        'mime_type': mime_type,
        'size': size,
        'risk_score': risk_score,
        'risk': risk,
        'suspicious': risk in {'HIGH', 'MEDIUM'},
        'indicators': indicators,
        'suspicious_keywords': suspicious_keywords,
        'double_extension': double_extension,
        'reason': '; '.join(indicators) if indicators else 'No significant attachment risk detected',
    }


def extract_attachments(message: Message):
    attachments = []
    for part in message.walk():
        if part.get_filename():
            attachments.append(analyze_attachment(part))
    return attachments


def analyze_email_attachments(message: Message):
    attachments = extract_attachments(message)
    suspicious_count = sum(1 for a in attachments if a['suspicious'])
    high_risk_count = sum(1 for a in attachments if a['risk'] == 'HIGH')
    medium_risk_count = sum(1 for a in attachments if a['risk'] == 'MEDIUM')
    overall_risk = 'HIGH' if high_risk_count else 'MEDIUM' if medium_risk_count else 'LOW'
    return {
        'attachments': attachments,
        'attachment_count': len(attachments),
        'suspicious_count': suspicious_count,
        'high_risk_count': high_risk_count,
        'medium_risk_count': medium_risk_count,
        'has_attachments': bool(attachments),
        'overall_risk': overall_risk,
    }


if __name__ == '__main__':
    from email import policy
    from email.parser import BytesParser

    test_email = b'''From: attacker@example.com\nTo: victim@example.com\nSubject: Urgent Document\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="BOUNDARY"\n\n--BOUNDARY\nContent-Type: text/plain\n\nPlease open the attached invoice.\n\n--BOUNDARY\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.pdf.exe"\n\nFake attachment content\n\n--BOUNDARY--\n'''
    message = BytesParser(policy=policy.default).parsebytes(test_email)
    result = analyze_email_attachments(message)
    print('\n===== TASK 17 ATTACHMENT ANALYSIS =====')
    print('Attachments:', result['attachment_count'])
    print('Suspicious:', result['suspicious_count'])
    print('High Risk:', result['high_risk_count'])
    print('Medium Risk:', result['medium_risk_count'])
    print('Overall Risk:', result['overall_risk'])
    for a in result['attachments']:
        print('\nFilename:', a['filename'])
        print('Extension:', a['extension'])
        print('MIME Type:', a['mime_type'])
        print('Size:', a['size'], 'bytes')
        print('Risk Score:', a['risk_score'])
        print('Risk:', a['risk'])
        print('Double Extension:', a['double_extension'])
        print('Suspicious Keywords:', a['suspicious_keywords'])
        print('Indicators:', a['indicators'])
