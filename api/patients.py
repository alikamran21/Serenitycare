"""
api/patients.py - Full patient CRUD.
Routing: if is_honeypot -> shadow_vault schema via raw SQL SET search_path
"""
import json, asyncio, uuid
from datetime import datetime, timezone
from api.common import (
    SessionLocal, User, Doctor, Patient, Appointment, ClinicalNote,
    log_forensic, flag_threat, get_user, mark_honeypot, honeypot_gate, 
    parse_body, get_token, get_client_ip, err, _headers, select, 
    SHADOW_PATIENTS, decode_token, scan_for_attacks, run_async
)
from sqlalchemy import text, func

async def _run(token, body, method, ip, ua):
    if not token:
        return 401, {"detail": "Not authenticated."}
    try:
        payload = decode_token(token)
    except ValueError as e:
        return 401, {"detail": str(e)}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        
        mark_honeypot(user, payload.get("honeypot", False))

        # --- GET: list patients ---
        if method == "GET":
            trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_LIST_PATIENTS", "patients")
            if trap:
                return 200, {"patients": SHADOW_PATIENTS}
                
            rows = await db.execute(
                select(Patient, Doctor)
                .join(Doctor, Patient.doc_id == Doctor.doc_id, isouter=True)
            )
            result = rows.all()
            
            patients = []
            for pat, doc in result:
                # 1. Fetch the closest upcoming scheduled appointment
                appt_query = await db.execute(
                    select(Appointment.scheduled_at)
                    .where(Appointment.mrn == pat.mrn, Appointment.status == "Scheduled")
                    .order_by(Appointment.scheduled_at.asc())
                    .limit(1)
                )
                next_appt = appt_query.scalar_one_or_none()
                next_appt_str = next_appt.strftime("%b %d, %Y @ %I:%M %p") if next_appt else "Unscheduled"
                
                # 2. Count the total number of clinical notes (representing sessions)
                note_query = await db.execute(
                    select(func.count(ClinicalNote.note_id))
                    .where(ClinicalNote.mrn == pat.mrn)
                )
                session_count = note_query.scalar_one()

                patients.append({
                    "mrn":              pat.mrn,
                    "full_name":        pat.full_name,
                    "diagnosis":        pat.primary_diagnosis,  
                    "active_treatment": pat.active_treatment,
                    "status":           pat.status,
                    "doctor":           doc.full_name if doc else None,
                    "doc_id":           pat.doc_id,
                    "user_id":          str(pat.user_id),
                    "next_appointment": next_appt_str,
                    "sessions":         session_count
                })
            return 200, {"patients": patients}

        # Write operations - doctor/admin only
        if user.role not in ("doctor", "admin"):
            return 403, {"detail": "Doctor or admin role required."}
            
        trap = await honeypot_gate(db, user, ip, ua, f"DOCTOR_{method}_PATIENT", "patients")
        if trap:
            return 200, {"detail": "Operation completed.", "mrn": "PT-SHADOW-FAKE"}

