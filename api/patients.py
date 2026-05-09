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

        # --- POST: add new patient ---
        if method == "POST":
            full_name  = str(body.get("full_name", "")).strip()
            email      = str(body.get("email", "")).strip().lower()
            diagnosis  = str(body.get("primary_diagnosis", "")).strip()
            treatment  = str(body.get("active_treatment", "")).strip()
            
            if not full_name or not email:
                return 400, {"detail": "full_name and email are required."}
                
            r = await db.execute(select(User).where(User.email == email))
            if r.scalar_one_or_none():
                return 409, {"detail": "A user with this email already exists."}
                
            new_uid = uuid.uuid4()
            mrn     = "PT-" + uuid.uuid4().hex[:6].upper()
            
            # Get the doctor's doc_id
            r_doc = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
            doc   = r_doc.scalar_one_or_none()
            doc_id = doc.doc_id if doc else None
            
            new_user = User(user_id=new_uid, email=email, role="patient", is_active=True)
            db.add(new_user)
            await db.flush()
            
            new_pat = Patient(mrn=mrn, user_id=new_uid, doc_id=doc_id,
                              full_name=full_name, primary_diagnosis=diagnosis,
                              active_treatment=treatment, status="Active")
            db.add(new_pat)
            await db.commit()
            
            await log_forensic(db, "PATIENT_ADD", "patients",
                               json.dumps({"mrn": mrn, "email": email}))
            return 201, {"detail": "Patient registered.", "mrn": mrn}

        # --- PUT: update diagnosis/treatment ---
        if method == "PUT":
            mrn = body.get("mrn")
            if not mrn: return 400, {"detail": "mrn required."}
            
            r   = await db.execute(select(Patient).where(Patient.mrn == mrn))
            pat = r.scalar_one_or_none()
            if not pat: return 404, {"detail": "Patient not found."}
            
            if "primary_diagnosis" in body: pat.primary_diagnosis = body["primary_diagnosis"]
            if "active_treatment"  in body: pat.active_treatment  = body["active_treatment"]
            if "status"            in body: pat.status            = body["status"]
            
            await db.commit()
            await log_forensic(db, "PATIENT_UPDATE", "patients", json.dumps({"mrn": mrn}))
            return 200, {"detail": "Patient updated."}

        # --- DELETE ---
        if method == "DELETE":
            mrn = body.get("mrn")
            if not mrn: return 400, {"detail": "mrn required."}
            
            r   = await db.execute(select(Patient).where(Patient.mrn == mrn))
            pat = r.scalar_one_or_none()
            if not pat: return 404, {"detail": "Patient not found."}
            
            # Delete user (cascades to patient via FK)
            r2  = await db.execute(select(User).where(User.user_id == pat.user_id))
            usr = r2.scalar_one_or_none()
            if usr: await db.delete(usr)
            else:   await db.delete(pat)
            
            await db.commit()
            await log_forensic(db, "PATIENT_DELETE", "patients", json.dumps({"mrn": mrn}))
            return 200, {"detail": "Patient deleted."}

    return 405, {"detail": "Method not allowed."}

def handler(request, context=None):
    M = "GET, POST, PUT, DELETE, OPTIONS"
    if request.method == "OPTIONS":
        return {"statusCode": 204, "headers": _headers(M), "body": ""}
    if request.method not in ("GET","POST","PUT","DELETE"):
        return err("Method not allowed.", 405, M)
        
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), body, request.method, ip, ua))
    
    return {"statusCode": status, "headers": _headers(M), "body": json.dumps(data)}
