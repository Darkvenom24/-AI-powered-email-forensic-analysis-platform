from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


# ============================================================
# PDF FORENSIC REPORT
# ============================================================

def _safe(value, default="Not Found"):
    """Return a printable value without exposing None."""
    if value is None or str(value).strip() == "":
        return default
    return str(value)


def _risk_color(score):
    score = int(score or 0)

    if score >= 70:
        return colors.HexColor("#dc2626")

    if score >= 40:
        return colors.HexColor("#d97706")

    return colors.HexColor("#16a34a")


def _risk_label(score):
    score = int(score or 0)

    if score >= 70:
        return "HIGH RISK"

    if score >= 40:
        return "MEDIUM RISK"

    return "LOW RISK"


def _header_footer(canvas, doc):
    """Professional header/footer for every page."""
    canvas.saveState()

    width, height = A4

    # Header line
    canvas.setStrokeColor(colors.HexColor("#d1d5db"))
    canvas.setLineWidth(0.6)
    canvas.line(
        18 * mm,
        height - 17 * mm,
        width - 18 * mm,
        height - 17 * mm,
    )

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#374151"))
    canvas.drawString(
        18 * mm,
        height - 13 * mm,
        "AI EMAIL THREAT DETECTOR"
    )

    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        width - 18 * mm,
        height - 13 * mm,
        "Digital Forensic Analysis Report"
    )

    # Footer
    canvas.setStrokeColor(colors.HexColor("#d1d5db"))
    canvas.line(
        18 * mm,
        14 * mm,
        width - 18 * mm,
        14 * mm,
    )

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawString(
        18 * mm,
        9 * mm,
        "For authorized security analysis only"
    )

    canvas.drawRightString(
        width - 18 * mm,
        9 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()


def _section_title(title, styles):
    return [
        Spacer(1, 5 * mm),
        Paragraph(title, styles["section"]),
        Spacer(1, 2 * mm),
    ]


def _key_value_table(rows, styles):
    data = []

    for key, value in rows:
        data.append([
            Paragraph(f"<b>{_safe(key)}</b>", styles["small"]),
            Paragraph(_safe(value), styles["small"]),
        ])

    table = Table(
        data,
        colWidths=[42 * mm, 130 * mm],
        repeatRows=0,
    )

    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#374151")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    return table


def _status_cell(status, styles):
    normalized = _safe(status, "NOT FOUND").upper()

    if normalized == "PASS":
        bg = "#dcfce7"
        fg = "#166534"

    elif normalized == "FAIL":
        bg = "#fee2e2"
        fg = "#991b1b"

    else:
        bg = "#f3f4f6"
        fg = "#4b5563"

    return Paragraph(
        f'<font color="{fg}"><b>{normalized}</b></font>',
        styles["small"],
    ), colors.HexColor(bg)


def generate_pdf_report(result, output_path):
    """
    Generate a professional forensic investigation report.

    Compatible with the existing Flask call:
        generate_pdf_report(result, pdf_path)
    """

    if not isinstance(result, dict):
        raise ValueError("Invalid analysis result.")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=23 * mm,
        bottomMargin=20 * mm,
        title="AI Email Threat Detector - Forensic Report",
        author="AI Email Threat Detector",
        subject="Email threat detection and forensic analysis",
    )

    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#111827"),
            spaceAfter=5,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#6b7280"),
        ),
        "section": ParagraphStyle(
            "SectionTitle",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#111827"),
            spaceBefore=4,
            spaceAfter=4,
        ),
        "heading3": ParagraphStyle(
            "Heading3Custom",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#374151"),
            spaceBefore=3,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "BodyCustom",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#374151"),
        ),
        "small": ParagraphStyle(
            "SmallCustom",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#374151"),
        ),
        "tiny": ParagraphStyle(
            "TinyCustom",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#6b7280"),
        ),
        "center": ParagraphStyle(
            "CenterCustom",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#374151"),
        ),
    }

    prediction = _safe(
        result.get("prediction"),
        "UNKNOWN"
    ).upper()

    confidence = result.get(
        "confidence",
        0
    )

    risk_score = int(
        result.get(
            "risk_score",
            0
        ) or 0
    )

    threat = _safe(
        result.get("threat"),
        _risk_label(risk_score)
    )

    forensics = result.get(
        "forensics",
        {}
    ) or {}

    risk_reasons = result.get(
        "risk_reasons",
        []
    ) or []

    urls = result.get(
        "urls",
        []
    ) or []

    ips = result.get(
        "ips",
        []
    ) or []

    ip_results = result.get(
        "ip_results",
        []
    ) or []

    generated_at = datetime.now().strftime(
        "%d %B %Y, %I:%M:%S %p"
    )

    story = []

    # ========================================================
    # COVER / EXECUTIVE SUMMARY
    # ========================================================

    story.append(Spacer(1, 8 * mm))

    story.append(
        Paragraph(
            "AI Email Threat Detector",
            styles["title"]
        )
    )

    story.append(
        Paragraph(
            "Digital Forensic Analysis Report",
            styles["subtitle"]
        )
    )

    story.append(Spacer(1, 7 * mm))

    summary_data = [
        [
            Paragraph("<b>Generated</b>", styles["small"]),
            Paragraph(generated_at, styles["small"]),
        ],
        [
            Paragraph("<b>Threat Level</b>", styles["small"]),
            Paragraph(
                f'<font color="{_risk_color(risk_score).hexval()}">'
                f"<b>{threat}</b></font>",
                styles["small"],
            ),
        ],
        [
            Paragraph("<b>ML Prediction</b>", styles["small"]),
            Paragraph(
                f"<b>{prediction}</b>",
                styles["small"],
            ),
        ],
        [
            Paragraph("<b>ML Confidence</b>", styles["small"]),
            Paragraph(
                f"<b>{_safe(confidence, 0)}%</b>",
                styles["small"],
            ),
        ],
        [
            Paragraph("<b>Risk Score</b>", styles["small"]),
            Paragraph(
                f'<font color="{_risk_color(risk_score).hexval()}">'
                f"<b>{risk_score}/100</b></font>",
                styles["small"],
            ),
        ],
    ]

    summary = Table(
        summary_data,
        colWidths=[48 * mm, 124 * mm],
    )

    summary.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])
    )

    story.append(summary)

    # ========================================================
    # THREAT ASSESSMENT
    # ========================================================

    story.extend(
        _section_title(
            "1. Threat Assessment",
            styles
        )
    )

    story.append(
        Paragraph(
            "The analysis combines machine-learning classification "
            "with URL, email-header, authentication, forensic and "
            "IP intelligence signals.",
            styles["body"],
        )
    )

    story.append(Spacer(1, 2 * mm))

    if risk_reasons:

        reason_rows = []

        for index, reason in enumerate(risk_reasons, start=1):

            reason_rows.append([
                Paragraph(
                    f"<b>{index}</b>",
                    styles["center"]
                ),
                Paragraph(
                    _safe(reason),
                    styles["small"]
                ),
            ])

        reason_table = Table(
            reason_rows,
            colWidths=[12 * mm, 160 * mm],
            repeatRows=0,
        )

        reason_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fef3c7")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )

        story.append(reason_table)

    else:

        story.append(
            Paragraph(
                "No specific risk reasons were reported.",
                styles["body"]
            )
        )

    # ========================================================
    # EMAIL FORENSICS
    # ========================================================

    story.extend(
        _section_title(
            "2. Email Forensics",
            styles
        )
    )

    forensic_rows = [
        ("From", forensics.get("from")),
        ("Reply-To", forensics.get("reply_to")),
        ("Return-Path", forensics.get("return_path")),
        ("Subject", forensics.get("subject")),
        ("Message-ID", forensics.get("message_id")),
    ]

    story.append(
        _key_value_table(
            forensic_rows,
            styles
        )
    )

    # ========================================================
    # AUTHENTICATION
    # ========================================================

    story.extend(
        _section_title(
            "3. Email Authentication",
            styles
        )
    )

    auth_data = [[
        Paragraph("<b>Protocol</b>", styles["small"]),
        Paragraph("<b>Status</b>", styles["small"]),
        Paragraph("<b>Interpretation</b>", styles["small"]),
    ]]

    auth_descriptions = {
        "SPF": "Sender IP authorization result.",
        "DKIM": "Email signature verification result.",
        "DMARC": "Domain authentication and alignment result.",
    }

    for name, key in (
        ("SPF", "spf"),
        ("DKIM", "dkim"),
        ("DMARC", "dmarc"),
    ):

        status_cell, bg = _status_cell(
            forensics.get(key),
            styles
        )

        auth_data.append([
            Paragraph(
                f"<b>{name}</b>",
                styles["small"]
            ),
            status_cell,
            Paragraph(
                auth_descriptions[name],
                styles["small"]
            ),
        ])

    auth_table = Table(
        auth_data,
        colWidths=[30 * mm, 35 * mm, 107 * mm],
    )

    auth_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(auth_table)

    # ========================================================
    # FORENSIC INDICATORS
    # ========================================================

    story.extend(
        _section_title(
            "4. Forensic Indicators",
            styles
        )
    )

    indicators = forensics.get(
        "indicators",
        []
    ) or []

    if indicators:

        indicator_rows = []

        for index, indicator in enumerate(
            indicators,
            start=1
        ):

            indicator_rows.append([
                Paragraph(
                    f"<b>{index}</b>",
                    styles["center"]
                ),
                Paragraph(
                    _safe(indicator),
                    styles["small"]
                ),
            ])

        indicator_table = Table(
            indicator_rows,
            colWidths=[12 * mm, 160 * mm],
        )

        indicator_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fee2e2")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )

        story.append(indicator_table)

    else:

        story.append(
            Paragraph(
                "No major forensic indicators detected.",
                styles["body"]
            )
        )

    # ========================================================
    # URL ANALYSIS
    # ========================================================

    story.extend(
        _section_title(
            "5. URL Threat Analysis",
            styles
        )
    )

    if urls:

        url_data = [[
            Paragraph("<b>URL</b>", styles["small"]),
            Paragraph("<b>Domain</b>", styles["small"]),
            Paragraph("<b>Risk</b>", styles["small"]),
            Paragraph("<b>Status</b>", styles["small"]),
        ]]

        for url in urls:

            url_risk = int(
                url.get(
                    "risk_score",
                    0
                ) or 0
            )

            suspicious = (
                "SUSPICIOUS"
                if url.get("suspicious", False)
                else "NOT SUSPICIOUS"
            )

            url_data.append([
                Paragraph(
                    _safe(url.get("url")),
                    styles["tiny"]
                ),
                Paragraph(
                    _safe(url.get("domain")),
                    styles["tiny"]
                ),
                Paragraph(
                    f"<b>{url_risk}/100</b>",
                    styles["small"]
                ),
                Paragraph(
                    suspicious,
                    styles["tiny"]
                ),
            ])

        url_table = Table(
            url_data,
            colWidths=[67 * mm, 45 * mm, 25 * mm, 35 * mm],
            repeatRows=1,
        )

        url_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )

        story.append(url_table)

        story.append(Spacer(1, 2 * mm))

        for index, url in enumerate(urls, start=1):

            url_indicators = url.get(
                "indicators",
                []
            ) or []

            if url_indicators:

                story.append(
                    Paragraph(
                        f"<b>URL {index} indicators:</b> "
                        + "; ".join(
                            _safe(item)
                            for item in url_indicators
                        ),
                        styles["tiny"],
                    )
                )

    else:

        story.append(
            Paragraph(
                "No URLs detected in the analyzed content.",
                styles["body"]
            )
        )

    # ========================================================
    # IP ANALYSIS
    # ========================================================

    story.extend(
        _section_title(
            "6. IP Intelligence & Geolocation",
            styles
        )
    )

    if ip_results:

        geo_data = [[
            Paragraph("<b>IP</b>", styles["small"]),
            Paragraph("<b>Type</b>", styles["small"]),
            Paragraph("<b>Country</b>", styles["small"]),
            Paragraph("<b>City / Region</b>", styles["small"]),
            Paragraph("<b>Organization</b>", styles["small"]),
        ]]

        for ip in ip_results:

            city_region = (
                f"{_safe(ip.get('city'), 'Unavailable')} / "
                f"{_safe(ip.get('region'), 'Unavailable')}"
            )

            geo_data.append([
                Paragraph(
                    _safe(ip.get("ip")),
                    styles["tiny"]
                ),
                Paragraph(
                    _safe(ip.get("type"), "Unknown"),
                    styles["tiny"]
                ),
                Paragraph(
                    _safe(ip.get("country"), "Unavailable"),
                    styles["tiny"]
                ),
                Paragraph(
                    city_region,
                    styles["tiny"]
                ),
                Paragraph(
                    _safe(ip.get("organization"), "Unavailable"),
                    styles["tiny"]
                ),
            ])

        geo_table = Table(
            geo_data,
            colWidths=[32 * mm, 25 * mm, 32 * mm, 42 * mm, 41 * mm],
            repeatRows=1,
        )

        geo_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )

        story.append(geo_table)

        coordinate_rows = []

        for ip in ip_results:

            latitude = ip.get("latitude")
            longitude = ip.get("longitude")

            if (
                latitude is not None
                and longitude is not None
            ):

                coordinate_rows.append([
                    _safe(ip.get("ip")),
                    f"{latitude}, {longitude}",
                ])

        if coordinate_rows:

            story.append(Spacer(1, 3 * mm))

            story.append(
                Paragraph(
                    "<b>Available Coordinates</b>",
                    styles["heading3"]
                )
            )

            story.append(
                _key_value_table(
                    coordinate_rows,
                    styles
                )
            )

    elif ips:

        story.append(
            Paragraph(
                "IP addresses were detected, but no geolocation "
                "records are currently available.",
                styles["body"]
            )
        )

        for ip in ips:

            story.append(
                Paragraph(
                    f"• {_safe(ip)}",
                    styles["small"]
                )
            )

    else:

        story.append(
            Paragraph(
                "No IP addresses were detected.",
                styles["body"]
            )
        )

    story.append(Spacer(1, 3 * mm))

    story.append(
        Paragraph(
            "<b>Geolocation limitation:</b> IP-based geolocation "
            "provides an approximate network location. It does not "
            "identify an attacker's exact physical location.",
            styles["tiny"],
        )
    )

    # ========================================================
    # INVESTIGATION CONCLUSION
    # ========================================================

    story.extend(
        _section_title(
            "7. Investigation Conclusion",
            styles
        )
    )

    conclusion = (
        f"The analyzed email was classified as <b>{prediction}</b> "
        f"with a machine-learning confidence of "
        f"<b>{_safe(confidence, 0)}%</b>. The combined forensic "
        f"risk score is <b>{risk_score}/100</b>, resulting in a "
        f"<b>{threat}</b> assessment."
    )

    story.append(
        Paragraph(
            conclusion,
            styles["body"]
        )
    )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.extend(
        _section_title(
            "8. Disclaimer",
            styles
        )
    )

    story.append(
        Paragraph(
            "This report is intended for authorized cybersecurity "
            "analysis, education and incident-response support. "
            "Automated ML predictions, URL heuristics and IP "
            "geolocation are indicators rather than definitive proof "
            "of malicious activity. Findings should be reviewed by a "
            "qualified security analyst before taking enforcement or "
            "attribution actions.",
            styles["tiny"],
        )
    )

    doc.build(
        story,
        onFirstPage=_header_footer,
        onLaterPages=_header_footer,
    )
