"""api/auditlogs.py - Admin: forensic ledger + security alerts."""
import json, asyncio
from api.common import (
    SessionLocal, ForensicLedger, SecurityAlert, ThreatActor,
    get_user, get_token, err, _headers, select, decode_token, run_async
)

async def _run(token, kind, skip, limit):
    if not token: return 401, {"detail": "Not authenticated."}
    try: decode_token(token)
    except: return 401, {"detail": "Invalid token."}

    async with SessionLocal() as db:
        user, error = await get_user(token, db)
        if error: return 401, {"detail": error}
        if user.role != "admin": return 403, {"detail": "Admin only."}

        if kind == "alerts":
            rows  = await db.execute(select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).offset(skip).limit(limit))
            items = rows.scalars().all()
            return 200, {"alerts": [{"id": a.alert_id, "title": a.alert_title,
                                      "description": a.description, "resolved": a.is_resolved,
                                      "created_at": a.created_at.isoformat() if a.created_at else None} for a in items]}

        if kind == "threats":
