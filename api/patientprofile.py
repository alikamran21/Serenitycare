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

