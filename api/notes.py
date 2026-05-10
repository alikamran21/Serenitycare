"""api/notes.py — Clinical notes GET / POST.
Honeypot path writes to shadow_vault.clinical_notes and logs to forensic_ledger.
"""
import json, uuid
from api.common import (
    SessionLocal, User, Patient, Doctor, ClinicalNote, ForensicLedger,
    log_forensic, get_user, mark_honeypot, honeypot_gate,
    parse_body, get_token, get_client_ip, err, _headers, select,
    decode_token, run_async, encrypt_field, decrypt_field
)
from sqlalchemy import text


async def _log_honeypot(db, ip, ua, action, table, detail):
    payload = json.dumps({"honeypot": True, "ip": ip, "ua": ua[:80], **detail})
    db.add(ForensicLedger(action_type=f"HONEYPOT_{action}", target_table=table, query_text=payload))
    await db.commit()


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
            mrn = body.get("mrn")
            if not mrn and user.role == "patient":
                r   = await db.execute(select(Patient).where(Patient.user_id == user.user_id))
                pat = r.scalar_one_or_none()
                mrn = pat.mrn if pat else None
            if not mrn: return 400, {"detail": "mrn required."}

            if trap:
                rows = await db.execute(
                    text("SELECT note_id, notes_text, doc_id, created_at "
                         "FROM shadow_vault.clinical_notes WHERE mrn=:mrn "
                         "ORDER BY created_at DESC"),
                    {"mrn": mrn}
                )
                notes = [{"note_id": str(r.note_id),
                          "notes_text": r.notes_text,
                          "doc_id": r.doc_id,
                          "created_at": r.created_at.isoformat() if r.created_at else None}
                         for r in rows]
                return 200, {"notes": notes}

            rows = await db.execute(
                select(ClinicalNote).where(ClinicalNote.mrn == mrn)
                .order_by(ClinicalNote.created_at.desc())
            )
            notes = rows.scalars().all()
            return 200, {"notes": [{"note_id": str(n.note_id),
                                    "notes_text": decrypt_field(n.notes_text),
                                    "doc_id": n.doc_id,
                                    "created_at": n.created_at.isoformat() if n.created_at else None}
                                   for n in notes]}

        # POST
        if user.role not in ("doctor", "admin"):
            return 403, {"detail": "Only doctors can write notes."}

        notes_text = str(body.get("notes_text", "")).strip()
        mrn        = body.get("mrn")
        if not notes_text: return 400, {"detail": "notes_text required."}
        if not mrn:        return 400, {"detail": "mrn required."}

        if trap:
            note_id = str(uuid.uuid4())
            await db.execute(
                text("INSERT INTO shadow_vault.clinical_notes "
                     "(note_id, mrn, doc_id, notes_text) "
                     "VALUES (:nid, :mrn, 'DOC-001', :txt)"),
                {"nid": note_id, "mrn": mrn, "txt": notes_text}
            )
            await _log_honeypot(db, ip, ua, "INSERT_NOTE", "shadow_vault.clinical_notes",
                                {"mrn": mrn, "note_id": note_id,
                                 "preview": notes_text[:120]})
            return 200, {"detail": "Note saved."}

        r_doc = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
        doc   = r_doc.scalar_one_or_none()
        db.add(ClinicalNote(note_id=uuid.uuid4(), mrn=mrn,
                            doc_id=doc.doc_id if doc else None,
                            notes_text=encrypt_field(notes_text)))
        await db.commit()
        await log_forensic(db, "NOTE_SAVED", "clinical_notes", json.dumps({"mrn": mrn}))
        return 200, {"detail": "Note saved successfully."}


def handler(request, context=None):
    M = "GET, POST, OPTIONS"
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers(M), "body": ""}
    if request.method not in ("GET", "POST"): return err("Method not allowed.", 405, M)
    body   = parse_body(request)
    ip     = get_client_ip(request)
    ua     = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), body, request.method, ip, ua))
    return {"statusCode": status, "headers": _headers(M), "body": json.dumps(data)}
