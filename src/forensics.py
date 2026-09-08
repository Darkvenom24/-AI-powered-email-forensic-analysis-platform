from email import policy
from email.parser import BytesParser
import re


def parse_email(raw_bytes):

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_bytes)

    return message


def get_email_body(message):

    body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:
                    body += part.get_content()
                except Exception:
                    pass

    else:

        try:
            body = message.get_content()
        except Exception:
            body = ""

    return body


def extract_header_ips(message):

    headers = []

    for received in message.get_all(
        "Received",
        []
    ):
        headers.append(received)

    text = "\n".join(headers)

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    return list(
        dict.fromkeys(
            re.findall(pattern, text)
        )
    )


def analyze_headers(message):

    result = {

        "from": message.get(
            "From",
            "Not Found"
        ),

        "reply_to": message.get(
            "Reply-To",
            "Not Found"
        ),

        "return_path": message.get(
            "Return-Path",
            "Not Found"
        ),

        "subject": message.get(
            "Subject",
            "Not Found"
        ),

        "message_id": message.get(
            "Message-ID",
            "Not Found"
        ),

        "received": message.get_all(
            "Received",
            []
        ),

        "spf": "Not Found",

        "dkim": "Not Found",

        "dmarc": "Not Found",

        "indicators": []
    }


    # Authentication Results

    auth = message.get(
        "Authentication-Results",
        ""
    ).lower()


    # SPF

    if "spf=pass" in auth:

        result["spf"] = "PASS"

    elif "spf=fail" in auth:

        result["spf"] = "FAIL"

        result["indicators"].append(
            "SPF authentication failed"
        )


    # DKIM

    if "dkim=pass" in auth:

        result["dkim"] = "PASS"

    elif "dkim=fail" in auth:

        result["dkim"] = "FAIL"

        result["indicators"].append(
            "DKIM authentication failed"
        )


    # DMARC

    if "dmarc=pass" in auth:

        result["dmarc"] = "PASS"

    elif "dmarc=fail" in auth:

        result["dmarc"] = "FAIL"

        result["indicators"].append(
            "DMARC authentication failed"
        )


    # From / Reply-To mismatch

    sender = result["from"]

    reply = result["reply_to"]


    sender_match = re.search(
        r"@([\w.-]+)",
        sender
    )

    reply_match = re.search(
        r"@([\w.-]+)",
        reply
    )


    if sender_match and reply_match:

        sender_domain = (
            sender_match.group(1).lower()
        )

        reply_domain = (
            reply_match.group(1).lower()
        )


        if sender_domain != reply_domain:

            result["indicators"].append(
                "From and Reply-To domains do not match"
            )


    # Received headers

    if not result["received"]:

        result["indicators"].append(
            "No Received header found"
        )


    return result