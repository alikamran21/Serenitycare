"""
app.py — Phantasm-DB Flask entry point.
Bridges Vercel-style handlers to Flask routes.

New features:
  - /api/canary       -> Canary Token PDF (honeypot decoy document)
  - /api/canary/ping  -> Beacon receiver (fires when attacker opens PDF)
  - /api/waf-alert    -> WAF alert receiver (ModSecurity -> DB bridge)
  - ModSecurity WAF   -> Handled at nginx layer (see nginx.conf + modsec/)
"""
import os, logging
from flask import Flask, request, Response
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from api.health         import handler as health_handler
from api.lookup         import handler as lookup_handler
from api.verifyotp      import handler as verifyotp_handler
from api.patients       import handler as patients_handler
from api.notes          import handler as notes_handler
from api.appointment    import handler as appointment_handler
from api.tasks          import handler as tasks_handler
from api.doctorprofile  import handler as doctorprofile_handler
from api.patientprofile import handler as patientprofile_handler
from api.auditlogs      import handler as auditlogs_handler
from api.adminexplorer  import handler as adminexplorer_handler
from api.ping           import handler as ping_handler
from api.canary         import handler as canary_handler    # NEW: Canary PDF
from api.wafalert       import handler as wafalert_handler  # NEW: WAF->DB bridge

app = Flask(__name__)


class VercelRequest:
    def __init__(self, flask_req):
        self.method  = flask_req.method
        self.headers = dict(flask_req.headers)
        self.body    = flask_req.get_data()
        self.args    = flask_req.args


def flask_response(result: dict) -> Response:
    """
    Convert handler result dict to Flask Response.
    Handles binary payloads (PDF downloads, 1x1 GIF beacon pixels)
    via the _binary flag.
    """
    body = result.get("body", "")
    if result.get("_binary") and isinstance(body, bytes):
        resp = Response(body, status=result.get("statusCode", 200))
    else:
        resp = Response(body, status=result.get("statusCode", 200))
    for k, v in result.get("headers", {}).items():
        resp.headers[k] = v
    return resp


def make_route(fn, name):
    def view():
        return flask_response(fn(VercelRequest(request)))
    view.__name__ = name
    return view


ROUTES = [
    # ── Existing routes ───────────────────────────────────────────────
    ("/api/health",         health_handler,         ["GET",  "OPTIONS"]),
    ("/api/lookup",         lookup_handler,         ["POST", "OPTIONS"]),
    ("/api/verifyotp",      verifyotp_handler,      ["POST", "OPTIONS"]),
    ("/api/patients",       patients_handler,       ["GET",  "POST", "PUT", "DELETE", "OPTIONS"]),
    ("/api/notes",          notes_handler,          ["GET",  "POST", "OPTIONS"]),
    ("/api/appointment",    appointment_handler,    ["GET",  "POST", "OPTIONS"]),
    ("/api/tasks",          tasks_handler,          ["GET",  "POST", "OPTIONS"]),
    ("/api/doctorprofile",  doctorprofile_handler,  ["GET",  "OPTIONS"]),
    ("/api/patientprofile", patientprofile_handler, ["GET",  "OPTIONS"]),
    ("/api/auditlogs",      auditlogs_handler,      ["GET",  "OPTIONS"]),
    ("/api/adminexplorer",  adminexplorer_handler,  ["GET",  "OPTIONS"]),
    ("/api/ping",           ping_handler,           ["GET",  "OPTIONS"]),
    # ── Canary Token routes (NEW) ─────────────────────────────────────
    # /api/canary       -> serves fake classified PDF to honeypot attacker
    # /api/canary/ping  -> silent GIF beacon; fires when attacker opens PDF
    #                      and logs their REAL IP (bypasses VPN used on web app)
    ("/api/canary",      canary_handler,  ["GET", "OPTIONS"]),
    ("/api/canary/ping", canary_handler,  ["GET", "OPTIONS"]),
    # ── WAF alert bridge (NEW) ────────────────────────────────────────
    # ModSecurity in nginx POSTs here when it blocks an attack.
    # This writes the attacker IP into monitor.threat_actors automatically,
    # without the Flask business logic needing to scan requests.
    ("/api/waf-alert",   wafalert_handler, ["POST", "GET", "OPTIONS"]),
]

for path, fn, methods in ROUTES:
    endpoint = path.lstrip("/").replace("/", "_").replace("-", "_")
    app.add_url_rule(path, endpoint=endpoint,
                     view_func=make_route(fn, endpoint), methods=methods)


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    try:
        from api.common import run_async, get_session_maker
        from sqlalchemy import text as _text
        async def _warmup():
            maker = get_session_maker()
            async with maker() as _db:
                await _db.execute(_text("SELECT 1"))
        run_async(_warmup())
        logging.getLogger(__name__).info("DB warmup complete.")
    except Exception as _e:
        logging.getLogger(__name__).warning(
            "DB warmup failed — backend will still start, first request may be slower: %s", _e
        )

    app.run(host="0.0.0.0", port=port, debug=debug)
