""api/doctorprofile.py — Doctor's own profile."""
import json, asyncio
from api.common import (
    SessionLocal, Doctor, get_user, mark_honeypot, honeypot_gate,
    get_token, get_client_ip, err, _headers, select, SHADOW_DOCTOR, decode_token,
    run_async
)

async def _run(token, ip, ua):
    if not token: return 401, {"detail": "Not authenticated."}
    try: payload = decode_token(token)
    except ValueError as e: return 401, {"detail": str(e)}
    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        mark_honeypot(user, payload.get("honeypot", False))
        trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_PROFILE_VIEW", "doctors")
        if trap: return 200, SHADOW_DOCTOR
        r   = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
        doc = r.scalar_one_or_none()
        return 200, {
            "doc_id":        doc.doc_id if doc else None,
            "full_name":     doc.full_name if doc else user.email,
            "specialization":doc.specialization if doc else None,
            "email":         user.email,
            "role":          user.role,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers("GET, OPTIONS"), "body": ""}
    if request.method != "GET":     return err("Method not allowed.", 405, "GET, OPTIONS")
    ip = get_client_ip(request); ua = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), ip, ua))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
