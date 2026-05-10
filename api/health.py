import json, logging
from api.common import SessionLocal, run_async, _headers, preflight
from sqlalchemy import text

log = logging.getLogger(__name__)

async def _check_db():
    try:
        async with SessionLocal() as db:
            await db.execute(text("SELECT 1"))
        return True, None
    except Exception as e:
        log.error("DB health check failed: %s", e)
        return False, str(e)

def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight("GET, OPTIONS")
    db_ok, db_err = run_async(_check_db())
    body = {"status": "ok" if db_ok else "degraded", "service": "SerenityEHR"}
    if db_ok:
        body["db"] = "connected"
    else:
        body["db"] = "unavailable"
        body["db_error"] = db_err
    return {
        "statusCode": 200 if db_ok else 503,
        "headers": _headers("GET, OPTIONS"),
        "body": json.dumps(body),
    }
