"""
api/canary.py — Canary Token PDF Generator (Honeypot Feature)

When an attacker (with a honeypot JWT) requests a "medical report" PDF,
this endpoint:
  1. Generates a unique canary token ID tied to the attacker's session.
  2. Embeds a tracking URL (canary beacon) inside the PDF as a clickable
     link AND as a 1x1 hidden image tag — both phone home on open.
  3. Logs the canary token to monitor.threat_actors so the admin can
     correlate "PDF opened" callbacks with the original attacker session.
  4. Returns the PDF as a binary download.

When the attacker opens the PDF on their local machine (even behind a VPN),
the PDF reader fetches the embedded URL, revealing their TRUE IP address.
"""

import io, json, uuid, logging, os
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from api.common import (
    SessionLocal, get_user, mark_honeypot, honeypot_gate,
    get_token, get_client_ip, err, _headers, decode_token,
    run_async, ThreatActor, ForensicLedger, flag_threat
)
from sqlalchemy import text

log = logging.getLogger(__name__)

# ── Canary beacon base URL ───────────────────────────────────────────
# This is your server's public URL. The PDF will call back to:
#   GET /api/canary/ping?token=<uuid>&src=pdf
# When the attacker opens the PDF, their PDF reader fetches this URL
# and your server logs their real IP (bypassing any VPN they used on
# the web app, because PDF readers use the OS network stack directly).
#
# In production: replace with your actual public domain.
# In local testing: use an ngrok tunnel URL.
CANARY_BASE_URL = os.environ.get("CANARY_BASE_URL", "http://localhost:8080")


def _generate_canary_token() -> str:
    """Generate a unique UUID canary token for this PDF."""
    return str(uuid.uuid4())


def _build_pdf(patient: dict, canary_token: str, beacon_url: str) -> bytes:
    """
    Build a realistic-looking fake medical report PDF with canary tokens embedded.

    Two beacon mechanisms are embedded:
    1. A visible "Secure Portal" hyperlink (disguised as normal document chrome)
    2. A tiny 1x1 pixel image URL that auto-fetches on open (in Adobe Reader etc.)
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#0f766e"),
        spaceAfter=4,
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_CENTER,
        spaceAfter=2,
    )
    section_header = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=colors.HexColor("#0f766e"),
        spaceBefore=14,
        spaceAfter=6,
        borderPad=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#1e293b"),
        leading=15,
    )
    classified_style = ParagraphStyle(
        "Classified",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#dc2626"),
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#94a3b8"),
        alignment=TA_CENTER,
    )

    story = []

    # ── Header ───────────────────────────────────────────────────────
    story.append(Paragraph("SERENITY PSYCHIATRIC CARE", title_style))
    story.append(Paragraph("Confidential Patient Medical Report", subtitle_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%B %d, %Y  %H:%M UTC')}",
        subtitle_style,
    ))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f766e")))
    story.append(Spacer(1, 4))
    story.append(Paragraph("⚠  CLASSIFIED — AUTHORISED ACCESS ONLY  ⚠", classified_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dc2626"), dash=(3, 3)))
    story.append(Spacer(1, 10))

    # ── Patient Info Table ────────────────────────────────────────────
    story.append(Paragraph("Patient Identification", section_header))

    mrn = patient.get("mrn", "PT-???")
    name = patient.get("full_name", "Unknown")
    status = patient.get("status", "Active")
    doctor = patient.get("doctor", "Dr. Unknown")

    info_data = [
        ["Medical Record No.", mrn,       "Classification", status],
        ["Patient Name",       name,       "Primary Physician", doctor],
        ["Report Class",       "LEVEL-4",  "Document ID",   canary_token[:12].upper()],
    ]
    info_table = Table(info_data, colWidths=[1.5*inch, 2.2*inch, 1.5*inch, 2.0*inch])
    info_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#f0fdf4")),
        ("BACKGROUND",   (2, 0), (2, -1), colors.HexColor("#f0fdf4")),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",     (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",    (0, 0), (0, -1), colors.HexColor("#0f766e")),
        ("TEXTCOLOR",    (2, 0), (2, -1), colors.HexColor("#0f766e")),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING",      (0, 0), (-1, -1), 6),
    ]))
    story.append(info_table)

    # ── Clinical Summary ──────────────────────────────────────────────
    story.append(Paragraph("Clinical Summary", section_header))
    diag = patient.get("primary_diagnosis", "Classified — see secure terminal")
    treat = patient.get("active_treatment", "Refer to authorised clinician")
    story.append(Paragraph(f"<b>Primary Diagnosis:</b>  {diag}", body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Active Treatment Protocol:</b>  {treat}", body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report contains Protected Health Information (PHI) under HIPAA and is "
        "subject to strict confidentiality obligations. Unauthorised disclosure, copying, "
        "or distribution is prohibited and may constitute a criminal offence.",
        body_style,
    ))

    # ── Classified Notes ──────────────────────────────────────────────
    story.append(Paragraph("Restricted Clinical Notes", section_header))
    story.append(Paragraph(
        "<b>[EYES ONLY]</b> The following notes are accessible only to cleared personnel. "
        "This document has been digitally watermarked and access is tracked. "
        "Document integrity is verified via the Serenity Secure Portal.",
        body_style,
    ))
    story.append(Spacer(1, 8))

    # Fake classified notes table
    notes_data = [
        ["Session", "Date",        "Summary"],
        ["S-041",   "2025-07-14",  "Subject exhibited signs of enhanced cognitive load. Protocol V-7 adjusted."],
        ["S-042",   "2025-07-21",  "Memory consolidation test administered. Results: CLASSIFIED (Level-5 clearance required)."],
        ["S-043",   "2025-07-28",  "External liaison meeting. NDA counter-party: [REDACTED]. Status: active."],
        ["S-044",   "2025-08-04",  "Full psych evaluation complete. Refer to Annex-C (not in this document)."],
    ]
    notes_table = Table(notes_data, colWidths=[0.8*inch, 1.1*inch, 5.3*inch])
    notes_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#0f766e")),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID",          (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING",       (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(notes_table)

    # ── CANARY BEACON #1 — Hyperlink disguised as portal verification ─
    # When the PDF is opened and the user clicks "Verify", their IP is captured.
    # Some PDF readers (especially Adobe) also auto-fetch Action URLs.
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Document Verification", section_header))
    story.append(Paragraph(
        "This document is cryptographically sealed. To verify authenticity and log your "
        "access for compliance purposes, click the link below:",
        body_style,
    ))
    story.append(Spacer(1, 6))

    # The canary URL — clicking this reveals the opener's real IP
    verify_url = f"{beacon_url}?token={canary_token}&src=pdf&action=verify"
    story.append(Paragraph(
        f'<link href="{verify_url}" color="#0f766e"><u>🔐 Verify Document Authenticity — Serenity Secure Portal</u></link>',
        ParagraphStyle("Link", parent=body_style, fontSize=10, alignment=TA_CENTER),
    ))

    # ── CANARY BEACON #2 — 1x1 auto-fetch image (silent beacon) ─────
    # Adobe Reader and many other PDF viewers auto-fetch remote images.
    # This happens silently when the PDF is opened — no click required.
    # The server logs the fetching IP as the attacker's true IP.
    silent_url = f"{beacon_url}?token={canary_token}&src=pdf&action=open"
    story.append(Spacer(1, 6))
    # Embed as a tiny tracking image reference in the footer area
    story.append(Paragraph(
        f'<img src="{silent_url}" width="1" height="1"/>',
        ParagraphStyle("Beacon", parent=body_style, fontSize=1),
    ))

    # ── Footer ────────────────────────────────────────────────────────
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Serenity Psychiatric Care  •  Confidential  •  Document Ref: {canary_token[:8].upper()}  •  "
        f"Access to this document is logged and monitored.",
        footer_style,
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


async def _run(token, ip, ua, mrn_hint: str = None):
    """Main async handler for canary PDF generation."""
    if not token:
        return 401, None, "Not authenticated."
    try:
        payload = decode_token(token)
    except ValueError as e:
        return 401, None, str(e)

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error:
            return 401, None, error

        mark_honeypot(user, payload.get("honeypot", False))
        is_trap = getattr(user, "_is_honeypot", False)

        # Only serve canary PDFs to honeypot sessions
        # (real users would use a proper document system)
        if not is_trap:
            return 403, None, "Access restricted to patient portal."

        # Pick a patient record to embed in the fake PDF
        from api.common import SHADOW_PATIENTS
        patient = SHADOW_PATIENTS[0]  # default
        if mrn_hint:
            for p in SHADOW_PATIENTS:
                if p["mrn"] == mrn_hint:
                    patient = p
                    break

        # Generate unique canary token for this download
        canary_token = _generate_canary_token()
        beacon_url = f"{CANARY_BASE_URL}/api/canary/ping"

        # Log this canary issuance to the threat actor record
        try:
            reason = (
                f"CANARY_PDF_ISSUED | ip={ip} | mrn={patient['mrn']} | "
                f"canary_token={canary_token} | ua={ua[:80]}"
            )
            threat_id = await flag_threat(db, ip, reason, level="high")
            db.add(ForensicLedger(
                threat_id=threat_id,
                action_type="CANARY_PDF_DOWNLOAD",
                target_table="shadow_vault.patients",
                query_text=json.dumps({
                    "canary_token": canary_token,
                    "mrn": patient["mrn"],
                    "patient": patient["full_name"],
                    "ip": ip,
                    "ua": ua[:120],
                    "beacon_url": beacon_url,
                    "note": (
                        "PDF delivered to attacker. If canary fires, their real IP "
                        "will appear in monitor.threat_actors via /api/canary/ping"
                    ),
                }),
            ))
            await db.commit()
        except Exception as e:
            log.error("Failed to log canary issuance: %s", e)
            try:
                await db.rollback()
            except Exception:
                pass

        # Build the PDF
        pdf_bytes = _build_pdf(patient, canary_token, beacon_url)
        return 200, pdf_bytes, None


async def _run_ping(token_id: str, source: str, action: str, real_ip: str, ua: str):
    """
    Called when the attacker's PDF reader fetches the canary URL.
    Logs their REAL IP address (bypasses VPN used on the web app).
    """
    async with SessionLocal() as db:
        try:
            reason = (
                f"CANARY_FIRED | canary_token={token_id} | "
                f"real_ip={real_ip} | src={source} | action={action} | ua={ua[:80]}"
            )
            threat_id = await flag_threat(db, real_ip, reason, level="critical")
            db.add(ForensicLedger(
                threat_id=threat_id,
                action_type="CANARY_BEACON_FIRED",
                target_table="monitor.threat_actors",
                query_text=json.dumps({
                    "canary_token": token_id,
                    "real_ip": real_ip,
                    "source": source,
                    "action": action,
                    "ua": ua[:120],
                    "note": (
                        "Attacker opened the canary PDF. This IP is their TRUE IP, "
                        "not the VPN/proxy used during the web attack."
                    ),
                }),
            ))
            await db.commit()
            log.warning(
                "🚨 CANARY FIRED: token=%s real_ip=%s src=%s action=%s",
                token_id, real_ip, source, action,
            )
        except Exception as e:
            log.error("canary ping log error: %s", e)
            try:
                await db.rollback()
            except Exception:
                pass


def handler(request, context=None):
    """Route handler for both PDF download and canary ping endpoints."""
    from flask import request as flask_req

    if request.method == "OPTIONS":
        return {"statusCode": 204, "headers": _headers("GET, OPTIONS"), "body": ""}

    path = getattr(flask_req, "path", "") if flask_req else ""

    # ── /api/canary/ping — beacon fired when PDF is opened ───────────
    if "/ping" in path:
        if request.method != "GET":
            return err("Method not allowed.", 405, "GET, OPTIONS")

        args = request.args if hasattr(request, "args") else {}
        token_id = args.get("token", "unknown")
        source   = args.get("src",    "unknown")
        action   = args.get("action", "unknown")
        real_ip  = get_client_ip(request)
        ua       = (request.headers or {}).get("user-agent", "")

        run_async(_run_ping(token_id, source, action, real_ip, ua))

        # Return a 1x1 transparent GIF — looks like a legit tracking pixel
        gif_1x1 = (
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
            b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
            b"\x00\x00\x02\x02D\x01\x00;"
        )
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type":  "image/gif",
                "Cache-Control": "no-store",
                "Access-Control-Allow-Origin": "*",
            },
            "body": gif_1x1,
            "_binary": True,
        }

    # ── /api/canary — PDF download ────────────────────────────────────
    if request.method != "GET":
        return err("Method not allowed.", 405, "GET, OPTIONS")

    ip  = get_client_ip(request)
    ua  = (request.headers or {}).get("user-agent", "")
    args = request.args if hasattr(request, "args") else {}
    mrn = args.get("mrn", None)

    status, pdf_bytes, error = run_async(_run(get_token(request), ip, ua, mrn))

    if error:
        return err(error, status, "GET, OPTIONS")

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type":        "application/pdf",
            "Content-Disposition": 'attachment; filename="SerenityMedicalReport_Confidential.pdf"',
            "Cache-Control":       "no-store",
            "Access-Control-Allow-Origin": "*",
        },
        "body": pdf_bytes,
        "_binary": True,
    }
