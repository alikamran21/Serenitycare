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


