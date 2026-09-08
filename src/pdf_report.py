from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib.units import inch
from datetime import datetime
import os


def generate_pdf_report(result, output_path):

    # ==================================================
    # CREATE OUTPUT DIRECTORY
    # ==================================================

    output_directory = os.path.dirname(output_path)

    if output_directory:
        os.makedirs(output_directory, exist_ok=True)


    # ==================================================
    # PDF DOCUMENT
    # ==================================================

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )


    # ==================================================
    # STYLES
    # ==================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=15,
        spaceBefore=15,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=10,
        leading=14
    )


    # ==================================================
    # STORY
    # ==================================================

    story = []


    # ==================================================
    # TITLE
    # ==================================================

    story.append(
        Paragraph(
            "AI EMAIL THREAT DETECTION REPORT",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Email Threat Detection + Geolocation + Forensics",
            ParagraphStyle(
                "Subtitle",
                parent=styles["Normal"],
                alignment=TA_CENTER,
                fontSize=11
            )
        )
    )

    story.append(Spacer(1, 20))


    # ==================================================
    # REPORT INFORMATION
    # ==================================================

    story.append(
        Paragraph(
            "Report Information",
            heading_style
        )
    )

    report_info = [
        ["Generated On", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Threat Level", str(result.get("threat", "Unknown"))],
        ["ML Prediction", str(result.get("prediction", "Unknown"))],
        ["ML Confidence", f'{result.get("confidence", 0)}%'],
        ["Risk Score", f'{result.get("risk_score", 0)}/100']
    ]

    info_table = Table(
        report_info,
        colWidths=[1.8 * inch, 4.5 * inch]
    )

    info_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 7)
        ])
    )

    story.append(info_table)


    # ==================================================
    # EMAIL FORENSICS
    # ==================================================

    story.append(
        Paragraph(
            "Email Forensics",
            heading_style
        )
    )

    forensic = result.get("forensics", {})

    forensic_data = [
        ["Field", "Value"],
        ["From", str(forensic.get("from", "Not Found"))],
        ["Reply-To", str(forensic.get("reply_to", "Not Found"))],
        ["Return-Path", str(forensic.get("return_path", "Not Found"))],
        ["Subject", str(forensic.get("subject", "Not Found"))],
        ["Message-ID", str(forensic.get("message_id", "Not Found"))],
        ["SPF", str(forensic.get("spf", "Not Found"))],
        ["DKIM", str(forensic.get("dkim", "Not Found"))],
        ["DMARC", str(forensic.get("dmarc", "Not Found"))]
    ]

    forensic_table = Table(
        forensic_data,
        colWidths=[1.6 * inch, 4.7 * inch]
    )

    forensic_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6)
        ])
    )

    story.append(forensic_table)


    # ==================================================
    # FORENSIC INDICATORS
    # ==================================================

    story.append(
        Paragraph(
            "Forensic Indicators",
            heading_style
        )
    )

    indicators = forensic.get("indicators", [])

    if indicators:

        for indicator in indicators:

            story.append(
                Paragraph(
                    f"• {indicator}",
                    normal_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No major forensic indicators detected.",
                normal_style
            )
        )


    # ==================================================
    # URL ANALYSIS
    # ==================================================

    story.append(
        Paragraph(
            "URL Analysis",
            heading_style
        )
    )

    urls = result.get("urls", [])

    if urls:

        url_data = [
            [
                "URL",
                "Domain",
                "Risk",
                "Suspicious"
            ]
        ]

        for url in urls:

            url_data.append([
                str(url.get("url", "")),
                str(url.get("domain", "")),
                str(url.get("risk_score", "")),
                str(url.get("suspicious", ""))
            ])

        url_table = Table(
            url_data,
            colWidths=[
                2.2 * inch,
                1.7 * inch,
                0.8 * inch,
                1.0 * inch
            ]
        )

        url_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5)
            ])
        )

        story.append(url_table)

    else:

        story.append(
            Paragraph(
                "No URLs detected.",
                normal_style
            )
        )


    # ==================================================
    # IP GEOLOCATION
    # ==================================================

    story.append(
        Paragraph(
            "IP Geolocation",
            heading_style
        )
    )

    ip_results = result.get("ip_results", [])

    if ip_results:

        ip_data = [
            [
                "IP",
                "Type",
                "Country",
                "City",
                "Organization"
            ]
        ]

        for ip in ip_results:

            ip_data.append([
                str(ip.get("ip", "")),
                str(ip.get("type", "")),
                str(ip.get("country", "")),
                str(ip.get("city", "")),
                str(ip.get("organization", ""))
            ])


        ip_table = Table(
            ip_data,
            colWidths=[
                1.1 * inch,
                0.9 * inch,
                1.1 * inch,
                1.1 * inch,
                2.1 * inch
            ]
        )

        ip_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5)
            ])
        )

        story.append(ip_table)

    else:

        story.append(
            Paragraph(
                "No IP geolocation data available.",
                normal_style
            )
        )


    # ==================================================
    # IP COORDINATES
    # ==================================================

    coordinates_found = False

    for ip in ip_results:

        latitude = ip.get("latitude")
        longitude = ip.get("longitude")

        if latitude is not None and longitude is not None:

            coordinates_found = True

            story.append(
                Spacer(1, 8)
            )

            story.append(
                Paragraph(
                    f'IP {ip.get("ip")} Coordinates: '
                    f'{latitude}, {longitude}',
                    normal_style
                )
            )


    # ==================================================
    # FOOTER / DISCLAIMER
    # ==================================================

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "Disclaimer: IP geolocation provides approximate location information "
            "and should not be treated as the exact physical location of a person "
            "or device.",
            normal_style
        )
    )


    # ==================================================
    # BUILD PDF
    # ==================================================

    document.build(story)

    return output_path