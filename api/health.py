import json
from api.common import SessionLocal, run_async, _headers, preflight
from sqlalchemy import text

async def _check_db():
    try:
        async with SessionLocal() as db:
            await db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight("GET, OPTIONS")
    # Warm up DB connection pool on every health check call
    db_ok = run_async(_check_db())
    return {
        "statusCode": 200,
        "headers": _headers("GET, OPTIONS"),
        "body": json.dumps({"status": "ok", "service": "Phantasm-DB", "db": "connected" if db_ok else "warming up"})
    }
