"""
api/patients.py - Full patient CRUD.
Honeypot path: all operations go to shadow_vault.* so the attacker sees
real-looking changes. A rich forensic_ledger entry is written for every
action so the admin panel shows HONEYPOT-tagged rows.
Real data in public.* is never touched by honeypot tokens.
"""
import json, uuid
from datetime import datetime, timezone
from api.common import (
    SessionLocal, User, Doctor, Patient, Appointment, ClinicalNote,
    ForensicLedger, log_forensic, get_user, mark_honeypot, honeypot_gate,
    parse_body, get_token, get_client_ip, err, _headers, select,
    decode_token, run_async, encrypt_field, decrypt_field
)
from sqlalchemy import text, func


# ── helpers ──────────────────────────────────────────────────────────

async def _log_honeypot(db, ip: str, ua: str, action: str, table: str, detail: dict):
    """Write a forensic_ledger row clearly tagged as a honeypot action."""
    payload = json.dumps({"honeypot": True, "ip": ip, "ua": ua[:80], **detail})
    db.add(ForensicLedger(
        action_type=f"HONEYPOT_{action}",
        target_table=table,
        query_text=payload,
    ))
    await db.commit()


async def _shadow_next_appt(db, mrn: str) -> str:
    row = await db.execute(
        text("SELECT scheduled_at FROM shadow_vault.appointments "
             "WHERE mrn=:mrn AND status='Scheduled' ORDER BY scheduled_at LIMIT 1"),
        {"mrn": mrn}
    )
    r = row.fetchone()
    if r and r.scheduled_at:
        dt = r.scheduled_at
        return dt.strftime("%b %d, %Y @ %I:%M %p")
    return "Not Scheduled"


# ── main handler ─────────────────────────────────────────────────────

async def _run(token, body, method, ip, ua):
    if not token:
        return 401, {"detail": "Not authenticated."}
    try:
        payload = decode_token(token)
    except ValueError as e:
        return 401, {"detail": str(e)}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error:
            return 401, {"detail": error}

        mark_honeypot(user, payload.get("honeypot", False))

        # ── GET: list patients ────────────────────────────────────────
        if method == "GET":
            trap = await honeypot_gate(db, user, ip, ua, "DOCTOR_LIST_PATIENTS", "patients")
            if trap:
                shadow_rows = await db.execute(
                    text("SELECT mrn, doc_id, full_name, primary_diagnosis, "
                         "active_treatment, status FROM shadow_vault.patients "
                         "ORDER BY doc_id, mrn")
                )
                patients = []
                for r in shadow_rows:
                    next_appt = await _shadow_next_appt(db, r.mrn)
                    patients.append({
                        "mrn":              r.mrn,
                        "full_name":        r.full_name,
                        "diagnosis":        r.primary_diagnosis,
                        "active_treatment": r.active_treatment,
                        "status":           r.status,
                        "doctor":           r.doc_id,
                        "doc_id":           r.doc_id,
                        "next_appointment": next_appt,
                        "sessions":         0,
                    })
                return 200, {"patients": patients}

            # Real path — doctor sees only their own patients
            doctor_doc_id = None
            if user.role == "doctor":
                r_doc = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
                doc_rec = r_doc.scalar_one_or_none()
                doctor_doc_id = doc_rec.doc_id if doc_rec else None

            base_query = (
                select(Patient, Doctor)
                .join(Doctor, Patient.doc_id == Doctor.doc_id, isouter=True)
            )
            if user.role == "doctor" and doctor_doc_id:
                base_query = base_query.where(Patient.doc_id == doctor_doc_id)

            rows   = await db.execute(base_query)
            result = rows.all()
            if not result:
                return 200, {"patients": []}

            mrns = [pat.mrn for pat, _ in result]

            from sqlalchemy import case
            appt_subq = (
                select(Appointment.mrn, func.min(Appointment.scheduled_at).label("next_at"))
                .where(Appointment.mrn.in_(mrns), Appointment.status == "Scheduled")
                .group_by(Appointment.mrn)
                .subquery()
            )
            appt_rows = await db.execute(select(appt_subq))
            appt_map  = {r.mrn: r.next_at for r in appt_rows}

            note_rows = await db.execute(
                select(ClinicalNote.mrn, func.count(ClinicalNote.note_id).label("cnt"))
                .where(ClinicalNote.mrn.in_(mrns)).group_by(ClinicalNote.mrn)
            )
            note_map = {r.mrn: r.cnt for r in note_rows}

            patients = []
            for pat, doc in result:
                next_at = appt_map.get(pat.mrn)
                patients.append({
                    "mrn":              pat.mrn,
                    "full_name":        pat.full_name,
                    "diagnosis":        decrypt_field(pat.primary_diagnosis),
                    "active_treatment": decrypt_field(pat.active_treatment),
                    "status":           pat.status,
                    "doctor":           doc.full_name if doc else None,
                    "doc_id":           pat.doc_id,
                    "user_id":          str(pat.user_id),
                    "next_appointment": next_at.strftime("%b %d, %Y @ %I:%M %p") if next_at else "Unscheduled",
                    "sessions":         note_map.get(pat.mrn, 0),
                })
            return 200, {"patients": patients}

        # ── Write operations ─────────────────────────────────────────
        if user.role not in ("doctor", "admin"):
            return 403, {"detail": "Doctor or admin role required."}

        trap = await honeypot_gate(db, user, ip, ua, f"DOCTOR_{method}_PATIENT", "patients")

        # ── POST: register patient ────────────────────────────────────
        if method == "POST":
            full_name = str(body.get("full_name", "")).strip()
            email     = str(body.get("email",     "")).strip().lower()
            diagnosis = str(body.get("primary_diagnosis", "")).strip()
            treatment = str(body.get("active_treatment",  "")).strip()

            if not full_name or not email:
                return 400, {"detail": "full_name and email are required."}

            if trap:
                fake_mrn = "PT-" + uuid.uuid4().hex[:6].upper()
                # Insert into shadow_vault so attacker sees the new patient immediately
                fake_uid = str(uuid.uuid4())
                await db.execute(
                    text("INSERT INTO shadow_vault.patients "
                         "(mrn, user_id, doc_id, full_name, primary_diagnosis, active_treatment, status) "
                         "VALUES (:mrn, :uid, 'DOC-001', :name, :diag, :rx, 'Active') "
                         "ON CONFLICT (mrn) DO NOTHING"),
                    {"mrn": fake_mrn, "uid": fake_uid,
                     "name": full_name, "diag": diagnosis, "rx": treatment}
                )
                await _log_honeypot(db, ip, ua, "INSERT_PATIENT", "shadow_vault.patients",
                                    {"mrn": fake_mrn, "full_name": full_name,
                                     "email": email, "diagnosis": diagnosis})
                return 201, {"detail": "Patient registered.", "mrn": fake_mrn}

            # Real insert
            r = await db.execute(select(User).where(User.email == email))
            if r.scalar_one_or_none():
                return 409, {"detail": "A user with this email already exists."}
            new_uid = uuid.uuid4()
            mrn     = "PT-" + uuid.uuid4().hex[:6].upper()
            r_doc   = await db.execute(select(Doctor).where(Doctor.user_id == user.user_id))
            doc     = r_doc.scalar_one_or_none()
            doc_id  = doc.doc_id if doc else None
            db.add(User(user_id=new_uid, email=email, role="patient", is_active=True))
            await db.flush()
            db.add(Patient(mrn=mrn, user_id=new_uid, doc_id=doc_id,
                           full_name=full_name,
                           primary_diagnosis=encrypt_field(diagnosis),
                           active_treatment=encrypt_field(treatment),
                           status="Active"))
            await db.commit()
            await log_forensic(db, "PATIENT_ADD", "patients",
                               json.dumps({"mrn": mrn, "email": email}))
            return 201, {"detail": "Patient registered.", "mrn": mrn}

        # ── PUT: update patient ───────────────────────────────────────
        if method == "PUT":
            mrn = body.get("mrn")
            if not mrn:
                return 400, {"detail": "mrn required."}

            if trap:
                updates = {}
                if "primary_diagnosis" in body:
                    updates["primary_diagnosis"] = body["primary_diagnosis"]
                if "active_treatment" in body:
                    updates["active_treatment"] = body["active_treatment"]
                if "status" in body:
                    updates["status"] = body["status"]

                if updates:
                    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
                    updates["mrn"] = mrn
                    await db.execute(
                        text(f"UPDATE shadow_vault.patients SET {set_clause} WHERE mrn=:mrn"),
                        updates
                    )
                await _log_honeypot(db, ip, ua, "UPDATE_PATIENT", "shadow_vault.patients",
                                    {"mrn": mrn, "fields_changed": list(updates.keys())})
                return 200, {"detail": "Patient updated."}

            r   = await db.execute(select(Patient).where(Patient.mrn == mrn))
            pat = r.scalar_one_or_none()
            if not pat:
                return 404, {"detail": "Patient not found."}
            if "primary_diagnosis" in body: pat.primary_diagnosis = encrypt_field(body["primary_diagnosis"])
            if "active_treatment"  in body: pat.active_treatment  = encrypt_field(body["active_treatment"])
            if "status"            in body: pat.status            = body["status"]
            await db.commit()
            await log_forensic(db, "PATIENT_UPDATE", "patients", json.dumps({"mrn": mrn}))
            return 200, {"detail": "Patient updated."}

        # ── DELETE: remove patient ────────────────────────────────────
        if method == "DELETE":
            mrn = body.get("mrn")
            if not mrn:
                return 400, {"detail": "mrn required."}

            if trap:
                # Remove from shadow_vault so attacker sees them disappear
                await db.execute(
                    text("DELETE FROM shadow_vault.patients WHERE mrn=:mrn"),
                    {"mrn": mrn}
                )
                await _log_honeypot(db, ip, ua, "DELETE_PATIENT", "shadow_vault.patients",
                                    {"mrn": mrn})
                return 200, {"detail": "Patient deleted."}

            r   = await db.execute(select(Patient).where(Patient.mrn == mrn))
            pat = r.scalar_one_or_none()
            if not pat:
                return 404, {"detail": "Patient not found."}
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
    if request.method not in ("GET", "POST", "PUT", "DELETE"):
        return err("Method not allowed.", 405, M)
    body   = parse_body(request)
    ip     = get_client_ip(request)
    ua     = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), body, request.method, ip, ua))
    return {"statusCode": status, "headers": _headers(M), "body": json.dumps(data)}
