"""api/tasks.py — Daily tasks for patients (GET list + POST mark done)."""
import json, asyncio, uuid as _uuid
from datetime import datetime, timezone
from api.common import (
    SessionLocal, User, Patient, DailyTask, log_forensic,
    get_user, mark_honeypot, honeypot_gate, parse_body, get_token, get_client_ip,
    err, _headers, select, decode_token, run_async
)

SHADOW_TASKS = [
    {"task_id":"fake-1","task_title":"Morning Medication","is_done":False},
    {"task_id":"fake-2","task_title":"Breathing Exercise","is_done":False},
]

async def _run(token, body, method, ip, ua):
    if not token: return 401, {"detail": "Not authenticated."}
    try: payload = decode_token(token)
    except ValueError as e: return 401, {"detail": str(e)}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        mark_honeypot(user, payload.get("honeypot", False))
        trap = await honeypot_gate(db, user, ip, ua, f"TASKS_{method}", "daily_tasks")

        # Get patient MRN
        r   = await db.execute(select(Patient).where(Patient.user_id == user.user_id))
        pat = r.scalar_one_or_none()

        if method == "GET":
            if trap: return 200, {"tasks": SHADOW_TASKS}
            if not pat: return 404, {"detail": "Patient record not found."}
            rows = await db.execute(select(DailyTask).where(DailyTask.mrn == pat.mrn))
            tasks = rows.scalars().all()
            return 200, {"tasks": [{"task_id": str(t.task_id), "task_title": t.task_title,
                                     "task_description": t.task_description, "is_done": t.is_done} for t in tasks]}

        # POST — mark tasks done
        if trap: return 200, {"detail": "Tasks updated."}
        if not pat: return 404, {"detail": "Patient record not found."}

        task_ids = body.get("completed_task_ids", [])
        if not task_ids: return 400, {"detail": "completed_task_ids required."}

        for tid in task_ids:
            try:
                task_uuid = _uuid.UUID(str(tid))
            except (ValueError, AttributeError):
                continue  # Skip malformed IDs
            r2   = await db.execute(select(DailyTask).where(DailyTask.task_id == task_uuid))
            task = r2.scalar_one_or_none()
            if task and task.mrn == pat.mrn:
                task.is_done    = True
                task.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await log_forensic(db, "TASKS_UPDATED", "daily_tasks", json.dumps({"mrn": pat.mrn, "count": len(task_ids)}))
        return 200, {"detail": "Tasks updated successfully."}

def handler(request, context=None):
    M = "GET, POST, OPTIONS"
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers(M), "body": ""}
    if request.method not in ("GET","POST"): return err("Method not allowed.", 405, M)
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(get_token(request), body, request.method, ip, ua))
    return {"statusCode": status, "headers": _headers(M), "body": json.dumps(data)}
