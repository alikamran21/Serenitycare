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
