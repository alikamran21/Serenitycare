"""api/patientprofile.py - Patient's own profile view."""
import json, asyncio
from api.common import (
    SessionLocal, Patient, Appointment, Doctor, get_user, mark_honeypot, honeypot_gate,
    get_token, get_client_ip, err, _headers, select, SHADOW_PATIENT_SELF, decode_token,
    run_async
) # <--- FIXED: Added the missing closing parenthesis here!
async def _run(token, ip, ua):
    if not token: return 401, {"detail": "Not authenticated."}
    try: payload = decode_token(token)
    except ValueError as e: return 401, {"detail": str(e)}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        
        mark_honeypot(user, payload.get("honeypot", False))
        trap = await honeypot_gate(db, user, ip, ua, "PATIENT_PROFILE_VIEW", "patients")
        if trap: return 200, SHADOW_PATIENT_SELF

        # Join Patient with Doctor to get the Provider's name
        r = await db.execute(
            select(Patient, Doctor)
            .join(Doctor, Patient.doc_id == Doctor.doc_id, isouter=True)
            .where(Patient.user_id == user.user_id)
        )
        result = r.first()

        if not result:
            return 404, {"detail": "Patient record not found."}

        pat, doc = result

       # Next appointment
        next_appt = None
        if pat:
            ra = await db.execute(
                select(Appointment)
                .where(Appointment.mrn == pat.mrn, Appointment.status == "Scheduled")
                .order_by(Appointment.scheduled_at.asc()).limit(1)
            )
            appt = ra.scalar_one_or_none()
            if appt and appt.scheduled_at:
                # Format the date so it looks nice on the frontend
                next_appt = appt.scheduled_at.strftime("%b %d, %Y @ %I:%M %p")

        # The frontend expects 'medications' as a list array, so we format it here
        meds = [pat.active_treatment] if pat and pat.active_treatment else []

        # Return the EXACT keys the patient_portal.html is looking for
        return 200, {
            "mrn":              pat.mrn if pat else None,
            "full_name":        pat.full_name if pat else user.email,
            "diagnosis":        pat.primary_diagnosis if pat else None,
            "medications":      meds,
            "status":           pat.status if pat else None,
            "provider":         doc.full_name if doc else "Unassigned",
            "email":            user.email,
            "role":             user.role,
            "next_appointment": next_appt,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers("GET, OPTIONS"), "body": ""}
    if request.method != "GET":     return err("Method not allowed.", 405, "GET, OPTIONS")
    ip = get_client_ip(request); ua = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), ip, ua))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
