import os
from datetime import datetime

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

from config import REPORTS_DIR


def generate_forensic_report(
    case_id,
    email_data,
    risk_result,
    ml_result,
    header_result,
    ioc_result,
    geo_result,
    graph_result
):
    """
    Generate a downloadable forensic PDF report
    for an analyzed email case.
    """

    os.makedirs(
        REPORTS_DIR,
        exist_ok=True
    )

    report_path = os.path.join(
        REPORTS_DIR,
        f"{case_id}_forensic_report.pdf"
    )

    document = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "Normal",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13
    )

    story = []

    # -------------------------------------------------
    # TITLE
    # -------------------------------------------------

    story.append(
        Paragraph(
            "MailTrace AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Digital Email Forensic Investigation Report",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(
            1,
            15
        )
    )

    # -------------------------------------------------
    # CASE INFORMATION
    # -------------------------------------------------

    story.append(
        Paragraph(
            "1. Case Information",
            heading_style
        )
    )

    case_data = [
        ["Case ID", case_id],
        [
            "Generated At",
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        ],
        [
            "Filename",
            email_data.get(
                "filename",
                "Unknown"
            )
        ],
        [
            "Sender",
            email_data.get(
                "sender",
                "Unknown"
            )
        ],
        [
            "Receiver",
            email_data.get(
                "receiver",
                "Unknown"
            )
        ],
        [
            "Subject",
            email_data.get(
                "subject",
                "No Subject"
            )
        ]
    ]

    case_table = Table(
        case_data,
        colWidths=[
            120,
            380
        ]
    )

    case_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(case_table)

    # -------------------------------------------------
    # RISK ASSESSMENT
    # -------------------------------------------------

    story.append(
        Paragraph(
            "2. Threat Risk Assessment",
            heading_style
        )
    )

    risk_data = [
        [
            "Risk Score",
            str(
                risk_result.get(
                    "score",
                    0
                )
            ) + " / 100"
        ],
        [
            "Risk Level",
            risk_result.get(
                "level",
                "UNKNOWN"
            )
        ],
        [
            "Primary Threat",
            str(
                risk_result.get(
                    "primary_threat",
                    "Unknown"
                )
            ).replace(
                "_",
                " "
            ).title()
        ],
        [
            "Recommended Action",
            risk_result.get(
                "recommended_action",
                "Review the case."
            )
        ]
    ]

    risk_table = Table(
        risk_data,
        colWidths=[
            150,
            350
        ]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(risk_table)

    # -------------------------------------------------
    # ML ANALYSIS
    # -------------------------------------------------

    story.append(
        Paragraph(
            "3. Machine Learning Analysis",
            heading_style
        )
    )

    ml_prediction = ml_result.get(
        "display_name",
        "Unavailable"
    )

    ml_confidence = ml_result.get(
        "confidence_percent",
        0
    )

    story.append(
        Paragraph(
            f"<b>Classification:</b> "
            f"{ml_prediction}<br/>"
            f"<b>Confidence:</b> "
            f"{ml_confidence}%"
            ,
            normal_style
        )
    )

    top_predictions = ml_result.get(
        "top_predictions",
        []
    )

    if top_predictions:

        ml_rows = [
            [
                "Threat Class",
                "Probability"
            ]
        ]

        for item in top_predictions:

            ml_rows.append([
                item.get(
                    "name",
                    "Unknown"
                ),
                f"{item.get('probability', 0) * 100:.2f}%"
            ])

        ml_table = Table(
            ml_rows,
            colWidths=[
                300,
                200
            ]
        )

        ml_table.setStyle(
            TableStyle([
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                )
            ])
        )

        story.append(
            Spacer(
                1,
                8
            )
        )

        story.append(
            ml_table
        )

    # -------------------------------------------------
    # HEADER FORENSICS
    # -------------------------------------------------

    story.append(
        Paragraph(
            "4. Email Header Forensics",
            heading_style
        )
    )

    authentication = header_result.get(
        "authentication",
        {}
    )

    auth_data = [
        [
            "Authentication",
            "Status"
        ],
        [
            "SPF",
            authentication.get(
                "spf",
                "NOT_FOUND"
            )
        ],
        [
            "DKIM",
            authentication.get(
                "dkim",
                "NOT_FOUND"
            )
        ],
        [
            "DMARC",
            authentication.get(
                "dmarc",
                "NOT_FOUND"
            )
        ],
        [
            "Header Anomalies",
            str(
                header_result.get(
                    "anomaly_count",
                    0
                )
            )
        ]
    ]

    auth_table = Table(
        auth_data,
        colWidths=[
            250,
            250
        ]
    )

    auth_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            )
        ])
    )

    story.append(auth_table)

    # -------------------------------------------------
    # IOC ANALYSIS
    # -------------------------------------------------

    story.append(
        Paragraph(
            "5. Indicators of Compromise",
            heading_style
        )
    )

    summary = ioc_result.get(
        "summary",
        {}
    )

    ioc_data = [
        ["IOC Type", "Count"],
        [
            "Emails",
            str(
                summary.get(
                    "email_count",
                    0
                )
            )
        ],
        [
            "URLs",
            str(
                summary.get(
                    "url_count",
                    0
                )
            )
        ],
        [
            "Domains",
            str(
                summary.get(
                    "domain_count",
                    0
                )
            )
        ],
        [
            "IP Addresses",
            str(
                summary.get(
                    "ip_count",
                    0
                )
            )
        ],
        [
            "MD5",
            str(
                summary.get(
                    "md5_count",
                    0
                )
            )
        ],
        [
            "SHA1",
            str(
                summary.get(
                    "sha1_count",
                    0
                )
            )
        ],
        [
            "SHA256",
            str(
                summary.get(
                    "sha256_count",
                    0
                )
            )
        ]
    ]

    ioc_table = Table(
        ioc_data,
        colWidths=[
            250,
            250
        ]
    )

    ioc_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            )
        ])
    )

    story.append(ioc_table)

    # -------------------------------------------------
    # GEO INTELLIGENCE
    # -------------------------------------------------

    story.append(
        Paragraph(
            "6. Geo Intelligence",
            heading_style
        )
    )

    location = {}

    if geo_result:

        location = geo_result.get(
            "location"
        ) or {}

    if location:

        location_text = (
            f"<b>City:</b> "
            f"{location.get('city', 'Unknown')}<br/>"
            f"<b>Region:</b> "
            f"{location.get('region', 'Unknown')}<br/>"
            f"<b>Country:</b> "
            f"{location.get('country', 'Unknown')}<br/>"
            f"<b>Latitude:</b> "
            f"{location.get('latitude', 'Unknown')}<br/>"
            f"<b>Longitude:</b> "
            f"{location.get('longitude', 'Unknown')}<br/>"
            f"<b>Infrastructure:</b> "
            f"{location.get('isp', 'Unknown')}"
        )

    else:

        location_text = (
            "No city-level geo intelligence "
            "was available for this case."
        )

    story.append(
        Paragraph(
            location_text,
            normal_style
        )
    )

    # -------------------------------------------------
    # THREAT REASONS
    # -------------------------------------------------

    story.append(
        Paragraph(
            "7. Explainable Findings",
            heading_style
        )
    )

    reasons = risk_result.get(
        "reasons",
        []
    )

    if reasons:

        for reason in reasons:

            category = reason.get(
                "category",
                "Analysis"
            )

            severity = reason.get(
                "severity",
                "INFO"
            )

            message = reason.get(
                "message",
                ""
            )

            story.append(
                Paragraph(
                    f"<b>{category}</b> "
                    f"[{severity}] — {message}",
                    normal_style
                )
            )

            story.append(
                Spacer(
                    1,
                    4
                )
            )

    else:

        story.append(
            Paragraph(
                "No major suspicious indicators "
                "were identified.",
                normal_style
            )
        )

    # -------------------------------------------------
    # THREAT GRAPH SUMMARY
    # -------------------------------------------------

    story.append(
        Paragraph(
            "8. Threat Graph Summary",
            heading_style
        )
    )

    graph_statistics = graph_result.get(
        "statistics",
        {}
    ) if graph_result else {}

    story.append(
        Paragraph(
            f"<b>Graph Nodes:</b> "
            f"{graph_statistics.get('node_count', 0)}<br/>"
            f"<b>Graph Relationships:</b> "
            f"{graph_statistics.get('edge_count', 0)}",
            normal_style
        )
    )

    # -------------------------------------------------
    # DISCLAIMER
    # -------------------------------------------------

    story.append(
        Spacer(
            1,
            20
        )
    )

    story.append(
        Paragraph(
            "<b>Forensic Notice:</b> "
            "Geo intelligence represents approximate "
            "infrastructure-level or controlled demo "
            "location data. It must not be interpreted "
            "as an exact physical location of a sender.",
            normal_style
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    story.append(
        Paragraph(
            "Generated by MailTrace AI Threat Intelligence Engine",
            normal_style
        )
    )

    document.build(
        story
    )

    return report_path