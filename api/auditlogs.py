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
            rows  = await db.execute(select(ThreatActor).order_by(ThreatActor.flagged_at.desc()).offset(skip).limit(limit))
            items = rows.scalars().all()
            return 200, {"threats": [{"id": t.threat_id, "ip": str(t.ip_address) if t.ip_address else None,
                                       "reason": t.reason, "level": t.threat_level,
                                       "flagged_at": t.flagged_at.isoformat() if t.flagged_at else None} for t in items]}

        # Default: forensic ledger
        rows  = await db.execute(select(ForensicLedger).order_by(ForensicLedger.created_at.desc()).offset(skip).limit(limit))
        items = rows.scalars().all()
        
        logs_out = []
        for l in items:
            # Safely parse the payload (stored as a JSON string in query_text)
            payload_data = {}
            if l.query_text:
                try:
                    payload_data = json.loads(l.query_text)
                except:
                    # Fallback if it's just raw text
                    payload_data = {"raw": l.query_text}

            # Determine flags based on DB data
            is_trap = payload_data.get("honeypot", False)
            is_malicious = (l.threat_id is not None) or ("ATTACK" in str(l.action_type))
            
            # Map exactly to the keys Admin.html is looking for
            logs_out.append({
                "id": l.ledger_id,
                "timestamp": l.created_at.isoformat() if l.created_at else None,
                "action": l.action_type,
                "endpoint": l.target_table,
                "ip_address": payload_data.get("ip", "Internal System"),
                "is_malicious": is_malicious,
                "is_honeypot_action": is_trap,
                "response_status": 403 if is_malicious else 200,
                "payload": payload_data
            })

        return 200, {"logs": logs_out}
def handler(request, context=None):
    if request.method == "OPTIONS": return {"statusCode": 204, "headers": _headers("GET, OPTIONS"), "body": ""}
    if request.method != "GET":     return err("Method not allowed.", 405, "GET, OPTIONS")
    
    args  = getattr(request, "args", {}) or {}
    kind  = args.get("kind", "logs")
    skip  = int(args.get("skip", 0))
    limit = min(int(args.get("limit", 100)), 500)
    
    status, data = run_async(_run(get_token(request), kind, skip, limit))
    return {"statusCode": status, "headers": _headers("GET, OPTIONS"), "body": json.dumps(data)}
