
from datetime import datetime, timezone
import io

from .db import get_db

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
)

from xml.sax.saxutils import escape


# =========================================================
# SAFE VALUE
# =========================================================

def safe_value(value):
    """
    Safely convert any value to text for PDF generation.

    Prevents errors when database fields are NULL / None.
    """
    if value is None:
        return "-"

    value = str(value).strip()

    if not value:
        return "-"

    return escape(value)


# =========================================================
# PRIORITY MAPPING
# =========================================================

SEVERITY_PRIORITY = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
}


# =========================================================
# GENERATE TICKET ID
# =========================================================

def generate_ticket_id():
    """
    Generate a human-readable SOC ticket ID.

    Example:
    SOC-20260910-00001
    """

    db = get_db()

    today = datetime.now(timezone.utc).strftime("%Y%m%d")

    prefix = f"SOC-{today}-"

    row = db.execute(
        """
        SELECT ticket_id
        FROM tickets
        WHERE ticket_id LIKE ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (f"{prefix}%",),
    ).fetchone()

    if row is None:
        number = 1

    else:
        last_id = row["ticket_id"]

        # Safely handle NULL / invalid ticket IDs
        if not last_id:
            number = 1
        else:
            try:
                last_id = str(last_id)
                number = int(last_id.split("-")[-1]) + 1

            except (ValueError, IndexError, AttributeError):
                number = 1

    return f"{prefix}{number:05d}"


# =========================================================
# GET PRIORITY
# =========================================================

def get_priority(severity):
    """
    Convert alert severity into SOC priority.
    """

    severity = str(severity or "LOW").upper()

    return SEVERITY_PRIORITY.get(severity, "P4")


# =========================================================
# CREATE SOC TICKET
# =========================================================

def create_ticket(
    alert,
    event_id=None,
    alert_id=None,
    user_id=None
):
    """
    Create a SOC ticket from a detection alert.

    user_id ensures that every ticket belongs
    to the logged-in user.
    """

    if not alert:
        return None

    db = get_db()

    # -----------------------------------------------------
    # Generate ticket ID
    # -----------------------------------------------------

    ticket_id = generate_ticket_id()

    created_at = datetime.now(timezone.utc).isoformat()

    # -----------------------------------------------------
    # Severity / Priority
    # -----------------------------------------------------

    severity = str(
        alert.get("severity", "LOW")
    ).upper()

    priority = get_priority(severity)

    # -----------------------------------------------------
    # Ticket fields
    # -----------------------------------------------------

    title = alert.get(
        "title",
        "Security Alert"
    )

    description = alert.get(
        "description",
        ""
    )

    source_ip = alert.get(
        "source_ip"
    )

    rule_name = alert.get(
        "rule_name"
    )

    mitre_id = alert.get(
        "mitre_id"
    )

    # -----------------------------------------------------
    # Insert Ticket
    # -----------------------------------------------------

    cursor = db.execute(
        """
        INSERT INTO tickets (
            ticket_id,
            user_id,
            alert_id,
            event_id,
            created_at,
            title,
            description,
            severity,
            priority,
            status,
            assignee,
            source_ip,
            rule_name,
            mitre_id
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            ticket_id,
            user_id,
            alert_id,
            event_id,
            created_at,
            title,
            description,
            severity,
            priority,
            "OPEN",
            "SOC Analyst",
            source_ip,
            rule_name,
            mitre_id,
        ),
    )

    db.commit()

    # -----------------------------------------------------
    # Return created ticket
    # -----------------------------------------------------

    return {
        "id": cursor.lastrowid,
        "ticket_id": ticket_id,
        "user_id": user_id,
        "alert_id": alert_id,
        "event_id": event_id,
        "created_at": created_at,
        "title": title,
        "description": description,
        "severity": severity,
        "priority": priority,
        "status": "OPEN",
        "assignee": "SOC Analyst",
        "source_ip": source_ip,
        "rule_name": rule_name,
        "mitre_id": mitre_id,
    }


# =========================================================
# GENERATE TICKET PDF
# =========================================================

def generate_ticket_pdf(ticket):
    """
    Generate a professional SOC ticket PDF.

    Returns:
        BytesIO containing generated PDF.
    """

    if not ticket:
        raise ValueError("Ticket data is missing")

    buffer = io.BytesIO()

    # -----------------------------------------------------
    # Safely get ticket ID
    # -----------------------------------------------------

    ticket_id = ticket.get(
        "ticket_id",
        "UNKNOWN"
    )

    if not ticket_id:
        ticket_id = "UNKNOWN"

    # -----------------------------------------------------
    # PDF Document
    # -----------------------------------------------------

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
        title=f"SOC Ticket {ticket_id}",
        author="Mini SOC",
    )

    # -----------------------------------------------------
    # Styles
    # -----------------------------------------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TicketTitle",
        parent=styles["Title"],
        fontSize=20,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "TicketSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
        alignment=TA_CENTER,
        spaceAfter=20,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "TicketBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=15,
    )

    story = []

    # =====================================================
    # HEADER
    # =====================================================

    story.append(
        Paragraph(
            "SECURITY OPERATIONS CENTER",
            title_style
        )
    )

    story.append(
        Paragraph(
            f"SOC INCIDENT TICKET — {safe_value(ticket_id)}",
            subtitle_style
        )
    )

    # =====================================================
    # TICKET OVERVIEW
    # =====================================================

    story.append(
        Paragraph(
            "Ticket Overview",
            heading_style
        )
    )

    overview_data = [
        [
            "Ticket ID",
            safe_value(ticket.get("ticket_id"))
        ],
        [
            "Created",
            safe_value(ticket.get("created_at"))
        ],
        [
            "Severity",
            safe_value(ticket.get("severity"))
        ],
        [
            "Priority",
            safe_value(ticket.get("priority"))
        ],
        [
            "Status",
            safe_value(ticket.get("status"))
        ],
        [
            "Assignee",
            safe_value(ticket.get("assignee"))
        ],
    ]

    overview_table = Table(
        overview_data,
        colWidths=[120, 360]
    )

    overview_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#E8EEF5")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#1F2937")
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold"
                ),
                (
                    "FONTNAME",
                    (1, 0),
                    (1, -1),
                    "Helvetica"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),
            ]
        )
    )

    story.append(overview_table)

    # =====================================================
    # INCIDENT INFORMATION
    # =====================================================

    story.append(
        Paragraph(
            "Incident Information",
            heading_style
        )
    )

    incident_data = [
        [
            "Title",
            safe_value(ticket.get("title"))
        ],
        [
            "Source IP",
            safe_value(ticket.get("source_ip"))
        ],
        [
            "Detection Rule",
            safe_value(ticket.get("rule_name"))
        ],
        [
            "MITRE ATT&CK",
            safe_value(ticket.get("mitre_id"))
        ],
        [
            "Alert ID",
            safe_value(ticket.get("alert_id"))
        ],
        [
            "Event ID",
            safe_value(ticket.get("event_id"))
        ],
    ]

    incident_table = Table(
        incident_data,
        colWidths=[120, 360]
    )

    incident_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#E8EEF5")
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (0, -1),
                    "Helvetica-Bold"
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    9
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1")
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),
            ]
        )
    )

    story.append(incident_table)

    # =====================================================
    # DESCRIPTION
    # =====================================================

    story.append(
        Paragraph(
            "Incident Description",
            heading_style
        )
    )

    description = safe_value(
        ticket.get("description")
    )

    story.append(
        Paragraph(
            description,
            body_style
        )
    )

    # =====================================================
    # RESOLUTION / ANALYST NOTES
    # =====================================================

    story.append(
        Paragraph(
            "Analyst Response / Resolution",
            heading_style
        )
    )

    resolution = safe_value(
        ticket.get("resolution")
    ).replace("\n", "<br/>")

    story.append(
        Paragraph(
            resolution,
            body_style
        )
    )

    # =====================================================
    # FOOTER
    # =====================================================

    story.append(
        Spacer(1, 30)
    )

    story.append(
        Paragraph(
            "Generated by Mini SOC Security Operations Platform",
            subtitle_style
        )
    )

    # -----------------------------------------------------
    # Build PDF
    # -----------------------------------------------------

    document.build(story)

    buffer.seek(0)

    return buffer

