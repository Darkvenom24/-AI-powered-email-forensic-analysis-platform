# ============================================================
# SIH26106: Sample Preset Demonstration Emails
# ============================================================

PRESETS = {
    "fake_invoice": {
        "id": "fake_invoice",
        "title": "🚨 Fake Invoice Overdue (Executable Payload)",
        "badge": "CRITICAL RISK",
        "badge_class": "badge-critical",
        "sender": "billing@invoicing-quickbooks-alert.com",
        "receiver": "finance.dept@enterprise-solutions.com",
        "subject": "URGENT: Outstanding Overdue Invoice #INV-98421 - Final Demand",
        "raw_text": """From: billing@invoicing-quickbooks-alert.com
To: finance.dept@enterprise-solutions.com
Reply-To: collect-payments-dept@gmail.com
Subject: URGENT: Outstanding Overdue Invoice #INV-98421 - Final Demand
Date: Wed, 10 Sep 2026 09:14:22 +0000
Message-ID: <98421-urgent-notice@invoicing-quickbooks-alert.com>
Received: from mail.suspicious-bulletproof.nl (185.220.101.1) by mx.enterprise-solutions.com with SMTP; Wed, 10 Sep 2026 09:14:23 +0000
Authentication-Results: spf=fail (sender IP 185.220.101.1); dkim=none; dmarc=fail

Dear Customer,

Your corporate invoice #INV-98421 is now 14 days overdue. Immediate payment of $8,450.00 is required to prevent immediate suspension of all services and initiation of collection proceedings.

Please review the attached invoice breakdown and execute payment immediately:
http://185.220.101.1/downloads/invoice_statement.exe

Failure to settle this account immediately will result in permanent legal escalation.

Regards,
Accounts Receivable Department
QuickBooks Invoicing Automated Services
"""
    },
    "account_suspension": {
        "id": "account_suspension",
        "title": "⚠️ PayPal Account Suspension Phishing",
        "badge": "HIGH RISK",
        "badge_class": "badge-high",
        "sender": "security-team@paypa1-alert-support.net",
        "receiver": "user.investor@gmail.com",
        "subject": "Security Notice: Your Account Access Has Been Suspended",
        "raw_text": """From: security-team@paypa1-alert-support.net
To: user.investor@gmail.com
Reply-To: support-recover@paypa1-helpdesk.top
Subject: Security Notice: Your Account Access Has Been Suspended
Date: Wed, 10 Sep 2026 14:32:05 +0000
Message-ID: <sec-paypal-99124@paypa1-alert-support.net>
Received: from relay-host.ru (194.26.29.112) by mx.google.com with SMTP; Wed, 10 Sep 2026 14:32:06 +0000
Authentication-Results: spf=fail; dkim=none; dmarc=fail

Important Security Notice,

We detected multiple suspicious sign-in attempts to your PayPal account from an unrecognized device in Moscow, Russia (IP: 194.26.29.112).

To safeguard your funds and protect your identity, your account privileges have been temporarily restricted. You must verify your credentials immediately to restore full account access:

Click here to verify your identity:
https://login-paypal-verify-alert.com/account/restore?token=94218a8d

If you fail to verify within 24 hours, your account will be permanently closed.

Sincerely,
PayPal Security Operations Center
"""
    },
    "ceo_fraud": {
        "id": "ceo_fraud",
        "title": "💼 CEO Wire Transfer BEC (Executive Impersonation)",
        "badge": "HIGH RISK",
        "badge_class": "badge-high",
        "sender": "David Harrison <ceo@globex-enterprises.com>",
        "receiver": "accounts.payable@globex-enterprises.com",
        "subject": "Strictly Confidential: Urgent Wire Transfer Request",
        "raw_text": """From: David Harrison <ceo@globex-enterprises.com>
To: accounts.payable@globex-enterprises.com
Reply-To: david.harrison.consulting@offshore-advisors.ru
Subject: Strictly Confidential: Urgent Wire Transfer Request
Date: Wed, 10 Sep 2026 11:05:12 +0000
Message-ID: <exec-direct-0021@offshore-advisors.ru>
Received: from mail.offshore-advisors.ru (45.142.214.88) by mail.globex-enterprises.com with SMTP; Wed, 10 Sep 2026 11:05:13 +0000
Authentication-Results: spf=neutral; dkim=none; dmarc=none

Are you at your desk right now?

We are in the final closing stages of a confidential strategic asset acquisition. I need an urgent international wire transfer of $68,500 processed before 3:00 PM today.

Do not discuss this with anyone in the office yet due to NDA restrictions. Reply directly to this email so I can send you the foreign banking beneficiary details.

Send me a confirmation as soon as you review this.

David Harrison
Chief Executive Officer
Globex Enterprises
"""
    },
    "safe_corporate": {
        "id": "safe_corporate",
        "title": "🛡️ Legitimate Corporate Meeting (Safe / Benign)",
        "badge": "SAFE / LOW RISK",
        "badge_class": "badge-safe",
        "sender": "sarah.jenkins@techcorp-solutions.com",
        "receiver": "engineering-team@techcorp-solutions.com",
        "subject": "Sprint Retrospective & Q3 Product Architecture Review",
        "raw_text": """From: sarah.jenkins@techcorp-solutions.com
To: engineering-team@techcorp-solutions.com
Reply-To: sarah.jenkins@techcorp-solutions.com
Subject: Sprint Retrospective & Q3 Product Architecture Review
Date: Wed, 10 Sep 2026 16:00:00 +0000
Message-ID: <meeting-retro-1029@techcorp-solutions.com>
Received: from mail-relay.techcorp-solutions.com (142.250.190.46) by internal-mx.techcorp-solutions.com with ESMTP; Wed, 10 Sep 2026 16:00:01 +0000
Authentication-Results: spf=pass; dkim=pass; dmarc=pass

Hi Engineering Team,

Please review the agenda for our upcoming Sprint Retrospective scheduled for tomorrow at 2:00 PM EST via Google Meet.

Agenda:
1. Microservices deployment post-mortem
2. Supabase migration status update
3. SIH Hackathon platform milestones

Meeting link: https://meet.google.com/xyz-abcd-efg

Please add any additional discussion points or questions to the shared documentation page prior to the call.

Best regards,
Sarah Jenkins
Lead Technical Program Manager
TechCorp Solutions Inc.
"""
    }
}


def get_all_presets():
    return list(PRESETS.values())


def get_preset(preset_id):
    return PRESETS.get(preset_id)
