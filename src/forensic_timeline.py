from datetime import datetime


def _now_label():
    return datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')


def build_forensic_timeline(
    message=None,
    forensic_data=None,
    ioc_data=None,
    attachment_data=None,
    url_results=None,
    prediction=None,
    risk_score=None,
    threat=None,
):
    """Build a transparent analysis timeline.

    Generated timestamps describe when the local analysis pipeline performed
    each step. They are not claims about the attacker's activity time.
    Original Received header values are retained as separate evidence events.
    """
    timeline = []

    def add(event, description, category='Analysis', timestamp=None):
        timeline.append({
            'timestamp': timestamp or _now_label(),
            'event': event,
            'description': description,
            'category': category,
        })

    add('Analysis Started', 'Email analysis pipeline initialized.', 'Analysis')

    if message is not None:
        subject = message.get('Subject', 'Not Found')
        add('Email Parsed', f'Email structure parsed successfully. Subject: {subject}', 'Email')
    else:
        add('Email Parsed', 'Email content parsed for analysis.', 'Email')

    if forensic_data:
        received = forensic_data.get('received') or []
        add(
            'Headers Analyzed',
            f"Email headers and authentication fields analyzed ({len(received)} Received record(s)).",
            'Forensics',
        )
        for item in received:
            add('Received Header Evidence', str(item), 'Evidence', timestamp=None)
    else:
        add('Headers Analyzed', 'No forensic header data was available.', 'Forensics')

    add('Authentication Checked', 'SPF, DKIM and DMARC results evaluated.', 'Authentication')

    url_count = len(url_results or [])
    add('URLs Analyzed', f'{url_count} URL(s) analyzed using threat heuristics.', 'Network')

    ioc_count = 0
    if ioc_data:
        ioc_count = (
            int(ioc_data.get('url_count', 0) or 0)
            + int(ioc_data.get('ip_count', 0) or 0)
            + int(ioc_data.get('email_count', 0) or 0)
            + int(ioc_data.get('domain_count', 0) or 0)
        )
    add('IOCs Extracted', f'{ioc_count} indicator occurrence(s) extracted from the email.', 'Forensics')

    attachment_count = int((attachment_data or {}).get('attachment_count', 0) or 0)
    suspicious_count = int((attachment_data or {}).get('suspicious_count', 0) or 0)
    add(
        'Attachments Analyzed',
        f'{attachment_count} attachment(s) analyzed; {suspicious_count} suspicious attachment(s).',
        'Attachment',
    )

    if prediction:
        add(
            'AI Classification Completed',
            f'Machine-learning prediction: {prediction.upper()}.',
            'AI',
        )

    if risk_score is not None:
        add(
            'Risk Assessment Completed',
            f'Combined risk score: {risk_score}/100 ({threat or "UNKNOWN"}).',
            'Risk',
        )

    add('Analysis Completed', 'Forensic analysis pipeline completed successfully.', 'Analysis')
    return timeline
