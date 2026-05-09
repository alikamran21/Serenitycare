"""api/appointment.py — Appointments CRUD (schedule / cancel / list)."""
import json, asyncio, uuid
from datetime import datetime, timezone
from api.common import (
    SessionLocal, User, Patient, Doctor, Appointment, log_forensic,
    get_user, mark_honeypot, honeypot_gate, parse_body, get_token, get_client_ip,
    err, _headers, select, decode_token, run_async
)

async def _run(token, body, method, ip, ua):
    if not token: return 401, {"detail": "Not authenticated."}
    try: payload = decode_token(token)
    except ValueError as e: return 401, {"detail": str(e)}
    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        mark_honeypot(user, payload.get("honeypot", False))
        trap = await honeypot_gate(db, user, ip, ua, f"APPOINTMENT_{method}", "appointments")

        if method == "GET":
            if trap:
                return 200, {"appointments": [{"appt_id": "fake", "scheduled_at": "2025-08-12T10:00:00Z", "status": "Scheduled"}]}
            # Get patient's MRN
            mrn = body.get("mrn")
            if not mrn and user.role == "patient":
                r   = await db.execute(select(Patient).where(Patient.user_id == user.user_id))
                pat = r.scalar_one_or_none()
                mrn = pat.mrn if pat else None
            if not mrn: return 400, {"detail": "mrn required."}
            rows = await db.execute(
                select(Appointment).where(Appointment.mrn == mrn)
                .order_by(Appointment.scheduled_at.asc())
            )
            appts = rows.scalars().all()
            return 200, {"appointments": [
                {"appt_id": str(a.appt_id), "scheduled_at": a.scheduled_at.isoformat() if a.scheduled_at else None,
                 "is_urgent": a.is_urgent, "status": a.status} for a in appts
            ]}
                   # POST
        action = str(body.get("action", "schedule")).lower()
        mrn    = body.get("mrn")
        if not mrn: return 400, {"detail": "mrn required."}

        if trap:
            return 200, {"detail": f"Appointment {action}d."}

        if action == "cancel":
            appt_id = body.get("appt_id")
            if not appt_id: return 400, {"detail": "appt_id required to cancel."}
            r    = await db.execute(select(Appointment).where(Appointment.appt_id == appt_id))
            appt = r.scalar_one_or_none()
            if not appt: return 404, {"detail": "Appointment not found."}
            appt.status = "Cancelled"
            await db.commit()
            await log_forensic(db, "APPT_CANCEL", "appointments", json.dumps({"appt_id": appt_id}))
            return 200, {"detail": "Appointment cancelled."}

        # schedule
        dt_str = str(body.get("scheduled_at", "")).strip()
        if not dt_str: return 400, {"detail": "scheduled_at required."}
        try:
            dt = datetime.fromisoformat(dt_str.replace(" ", "T"))
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return 400, {"detail": "Invalid datetime. Use YYYY-MM-DDTHH:MM format."}
        r_doc = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
        doc   = r_doc.scalar_one_or_none()

        new_appt = Appointment(
            appt_id=uuid.uuid4(), mrn=mrn, scheduled_at=dt,
            doc_id=doc.doc_id if doc else None,
            is_urgent=body.get("is_urgent", False), status="Scheduled",
        )
        db.add(new_appt)
        await db.commit()
        await log_forensic(db, "APPT_SCHEDULE", "appointments", json.dumps({"mrn": mrn, "at": dt_str}))
        return 201, {"detail": "Appointment scheduled.", "appt_id": str(new_appt.appt_id)}

def handler(request, context=None):
    M = "GET, POST, OPTIONS"
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers(M), "body": ""}
    if request.method not in ("GET","POST"): return err("Method not allowed.", 405, M)
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), body, request.method, ip, ua))
    return {"statusCode": status, "headers": _headers(M), "body": json.dumps(data)}


