"""api/notes.py — Clinical notes (GET list + POST save into clinical_notes table)."""
import json, asyncio, uuid
from datetime import datetime, timezone
from api.common import (
    SessionLocal, User, Patient, Doctor, ClinicalNote, log_forensic,
    get_user, mark_honeypot, honeypot_gate, parse_body, get_token, get_client_ip,
    err, _headers, select, SHADOW_PATIENTS, decode_token, run_async
)

async def _run(token, body, method, ip, ua):
    if not token: return 401, {"detail": "Not authenticated."}
    try: payload = decode_token(token)
    except ValueError as e: return 401, {"detail": str(e)}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        mark_honeypot(user, payload.get("honeypot", False))
        trap = await honeypot_gate(db, user, ip, ua, f"NOTES_{method}", "clinical_notes")

        if method == "GET":
            if trap:
                return 200, {"notes": [{"notes_text": p.get("primary_diagnosis",""), "created_at": "2025-01-01"} for p in SHADOW_PATIENTS]}
            mrn = body.get("mrn")
            if not mrn and user.role == "patient":
                r   = await db.execute(select(Patient).where(Patient.user_id == user.user_id))
                pat = r.scalar_one_or_none()
                mrn = pat.mrn if pat else None
            if not mrn: return 400, {"detail": "mrn required."}
            rows = await db.execute(
                select(ClinicalNote).where(ClinicalNote.mrn == mrn)
                .order_by(ClinicalNote.created_at.desc())
            )
            notes = rows.scalars().all()
            return 200, {"notes": [{"note_id": str(n.note_id), "notes_text": n.notes_text,
                                    "doc_id": n.doc_id,
                                    "created_at": n.created_at.isoformat() if n.created_at else None}
                                   for n in notes]}

        # POST
        if user.role not in ("doctor", "admin"):
            return 403, {"detail": "Only doctors can write notes."}
        if trap:
            return 200, {"detail": "Note saved."}

        notes_text = str(body.get("notes_text", "")).strip()
        mrn        = body.get("mrn")
        if not notes_text: return 400, {"detail": "notes_text required."}
        if not mrn:        return 400, {"detail": "mrn required."}

        r_doc = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
        doc   = r_doc.scalar_one_or_none()

 
