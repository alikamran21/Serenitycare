"""
api/adminexplorer.py — Admin Postgres Explorer: queries all real public schema tables.
Only accessible to admin role. Returns live data from the database.
"""
import json
from api.common import (
    SessionLocal, User, Doctor, Patient, ClinicalNote, Appointment,
    DailyTask, OTPRequest, ForensicLedger, SecurityAlert, ThreatActor,
    LoginActivity, # FIXED: Added LoginActivity import
    get_user, get_token, err, _headers, select, decode_token, run_async,
    decrypt_field
)
from sqlalchemy import func

# ── Table registry — maps kind → query handler ───────────────────────
# public schema (real clinical data)
PUBLIC_TABLES = {
    "users", "doctors", "patients", "clinical_notes",
    "appointments", "daily_tasks", "otp_requests",
}
# monitor schema (SIEM data)
MONITOR_TABLES = {
    "threat_actors", "security_alerts", "forensic_ledger", "login_activity", # FIXED
}

async def _run(token, kind, skip, limit):
    if not token:
        return 401, {"detail": "Not authenticated."}
    try:
        decode_token(token)
    except Exception:
        return 401, {"detail": "Invalid token."}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error:
            return 401, {"detail": error}
        if user.role != "admin":
            return 403, {"detail": "Admin only."}

        # ── PUBLIC SCHEMA ────────────────────────────────────────────

        if kind == "users":
            rows = await db.execute(
                select(User).order_by(User.created_at.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(User.user_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["User ID", "Email", "Role", "Active", "Created At"],
                "rows": [
                    [str(u.user_id)[:18] + "…", u.email, u.role,
                     "✓" if u.is_active else "✗",
                     u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "—"]
                    for u in items
                ],
            }

        if kind == "doctors":
            rows = await db.execute(
                select(Doctor).order_by(Doctor.doc_id).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(Doctor.doc_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["Doctor ID", "Full Name", "Specialization"],
                "rows": [
                    [d.doc_id, d.full_name or "—", d.specialization or "—"]
                    for d in items
                ],
            }

        if kind == "patients":
            rows = await db.execute(
                select(Patient, Doctor)
                .join(Doctor, Patient.doc_id == Doctor.doc_id, isouter=True)
                .order_by(Patient.mrn).offset(skip).limit(limit)
            )
            items = rows.all()
            total = await db.scalar(select(func.count(Patient.mrn)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["MRN", "Full Name", "Primary Diagnosis", "Active Treatment", "Status", "Doctor", "Created At"],
                "rows": [
                    [
                        p.mrn,
                        p.full_name or "—",
                        decrypt_field(p.primary_diagnosis) or "—",
                        decrypt_field(p.active_treatment) or "—",
                        p.status or "—",
                        d.full_name if d else "—",
                        p.created_at.strftime("%Y-%m-%d") if p.created_at else "—",
                    ]
                    for p, d in items
                ],
            }

        if kind == "clinical_notes":
            rows = await db.execute(
                select(ClinicalNote, Doctor)
                .join(Doctor, ClinicalNote.doc_id == Doctor.doc_id, isouter=True)
                .order_by(ClinicalNote.created_at.desc()).offset(skip).limit(limit)
            )
            items = rows.all()
            total = await db.scalar(select(func.count(ClinicalNote.note_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["Note ID", "MRN", "Doctor", "Note (decrypted)", "Created At"],
                "rows": [
                    [
                        str(n.note_id)[:8] + "…",
                        n.mrn or "—",
                        d.full_name if d else "—",
                        (decrypt_field(n.notes_text) or "")[:120] + ("…" if len(decrypt_field(n.notes_text) or "") > 120 else ""),
                        n.created_at.strftime("%Y-%m-%d %H:%M") if n.created_at else "—",
                    ]
                    for n, d in items
                ],
            }

        if kind == "appointments":
            rows = await db.execute(
                select(Appointment, Doctor)
                .join(Doctor, Appointment.doc_id == Doctor.doc_id, isouter=True)
                .order_by(Appointment.scheduled_at.desc()).offset(skip).limit(limit)
            )
            items = rows.all()
            total = await db.scalar(select(func.count(Appointment.appt_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["Appt ID", "MRN", "Doctor", "Scheduled At", "Urgent", "Status"],
                "rows": [
                    [
                        str(a.appt_id)[:8] + "…",
                        a.mrn or "—",
                        d.full_name if d else "—",
                        a.scheduled_at.strftime("%Y-%m-%d %H:%M") if a.scheduled_at else "—",
                        "⚠ Yes" if a.is_urgent else "No",
                        a.status or "—",
                    ]
                    for a, d in items
                ],
            }

        if kind == "daily_tasks":
            rows = await db.execute(
                select(DailyTask).order_by(DailyTask.updated_at.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(DailyTask.task_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["Task ID", "MRN", "Title", "Done", "Updated At"],
                "rows": [
                    [
                        str(t.task_id)[:8] + "…",
                        t.mrn or "—",
                        (t.task_title or "—")[:60],
                        "✓" if t.is_done else "—",
                        t.updated_at.strftime("%Y-%m-%d %H:%M") if t.updated_at else "—",
                    ]
                    for t in items
                ],
            }

        if kind == "otp_requests":
            rows = await db.execute(
                select(OTPRequest).order_by(OTPRequest.created_at.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(OTPRequest.id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["ID", "User ID", "Expires At", "Used", "Created IP", "Created At"],
                "rows": [
                    [
                        str(o.id),
                        str(o.user_id)[:18] + "…" if o.user_id else "—",
                        o.expires_at.strftime("%H:%M:%S") if o.expires_at else "—",
                        "✓" if o.is_used else "—",
                        str(o.created_ip) if o.created_ip else "—",
                        o.created_at.strftime("%Y-%m-%d %H:%M") if o.created_at else "—",
                    ]
                    for o in items
                ],
            }

        # ── MONITOR SCHEMA ───────────────────────────────────────────
        
        # FIXED: Added logic to view the login_activity table
        if kind == "login_activity":
            rows = await db.execute(
                select(LoginActivity).order_by(LoginActivity.attempt_time.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(LoginActivity.login_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["Login ID", "Email Attempted", "IP Address", "Success", "Attempt Time"],
                "rows": [
                    [
                        str(l.login_id),
                        l.email_attempted or "—",
                        str(l.ip_address) if l.ip_address else "—",
                        "✓ Yes" if l.is_success else "✗ No",
                        l.attempt_time.strftime("%Y-%m-%d %H:%M:%S") if l.attempt_time else "—",
                    ]
                    for l in items
                ],
            }

        if kind == "threat_actors":
            rows = await db.execute(
                select(ThreatActor).order_by(ThreatActor.flagged_at.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(ThreatActor.threat_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["ID", "IP Address", "Threat Level", "Reason", "Flagged At"],
                "rows": [
                    [
                        f"ID-{t.threat_id}",
                        str(t.ip_address) if t.ip_address else "—",
                        (t.threat_level or "—").upper(),
                        (t.reason or "—")[:100],
                        t.flagged_at.strftime("%Y-%m-%d %H:%M:%S") if t.flagged_at else "—",
                    ]
                    for t in items
                ],
            }

        if kind == "security_alerts":
            rows = await db.execute(
                select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(SecurityAlert.alert_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["ID", "Title", "Description", "Resolved", "Created At"],
                "rows": [
                    [
                        str(a.alert_id),
                        a.alert_title or "—",
                        (a.description or "—")[:100],
                        "✓ Yes" if a.is_resolved else "✗ No",
                        a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "—",
                    ]
                    for a in items
                ],
            }

        if kind == "forensic_ledger":
            rows = await db.execute(
                select(ForensicLedger).order_by(ForensicLedger.created_at.desc()).offset(skip).limit(limit)
            )
            items = rows.scalars().all()
            total = await db.scalar(select(func.count(ForensicLedger.ledger_id)))
            return 200, {
                "kind": kind, "total": total,
                "headers": ["Ledger ID", "Action", "Table", "Payload", "Created At"],
                "rows": [
                    [
                        str(l.ledger_id),
                        l.action_type or "—",
                        l.target_table or "—",
                        (l.query_text or "—")[:100],
                        l.created_at.strftime("%Y-%m-%d %H:%M:%S") if l.created_at else "—",
                    ]
                    for l in items
                ],
            }

        return 400, {"detail": f"Unknown table kind: '{kind}'"}

def handler(request, context=None):
    M = "GET, OPTIONS"
    if request.method == "OPTIONS":
        return {"statusCode": 204, "headers": _headers(M), "body": ""}
    if request.method != "GET":
        return err("Method not allowed.", 405, M)

    args  = getattr(request, "args", {}) or {}
    kind  = args.get("kind", "").strip()
    skip  = int(args.get("skip", 0))
    limit = min(int(args.get("limit", 100)), 200)

    if not kind:
        return err("'kind' parameter is required.", 400, M)

    status, data = run_async(_run(get_token(request), kind, skip, limit))
    return {"statusCode": status, "headers": _headers(M), "body": json.dumps(data)}
