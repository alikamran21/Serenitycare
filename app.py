"""
app.py — Phantasm-DB Flask entry point.
Bridges Vercel-style handlers to Flask routes.
"""
import os, logging
from flask import Flask, request, Response
from dotenv import load_dotenv

load_dotenv()

# ── Enable logging so verifyotp debug lines appear in console/gunicorn output ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from api.health        import handler as health_handler
from api.lookup        import handler as lookup_handler
from api.verifyotp     import handler as verifyotp_handler
from api.patients      import handler as patients_handler
from api.notes         import handler as notes_handler
from api.appointment   import handler as appointment_handler
from api.tasks         import handler as tasks_handler
from api.doctorprofile import handler as doctorprofile_handler
from api.patientprofile import handler as patientprofile_handler
from api.auditlogs     import handler as auditlogs_handler
from api.ping          import handler as ping_handler

app = Flask(__name__)

class VercelRequest:
    def __init__(self, flask_req):
        self.method  = flask_req.method
        self.headers = dict(flask_req.headers)
        self.body    = flask_req.get_data()
        self.args    = flask_req.args

def flask_response(result: dict) -> Response:
    resp = Response(result.get("body", ""), status=result.get("statusCode", 200))
    for k, v in result.get("headers", {}).items():
        resp.headers[k] = v
    return resp

def make_route(fn, name):
    def view():
        return flask_response(fn(VercelRequest(request)))
    view.__name__ = name
    return view

ROUTES = [
    ("/api/health",          health_handler,         ["GET",  "OPTIONS"]),
    ("/api/lookup",          lookup_handler,         ["POST", "OPTIONS"]),
    ("/api/verifyotp",       verifyotp_handler,      ["POST", "OPTIONS"]),
    ("/api/patients",        patients_handler,       ["GET",  "POST", "PUT", "DELETE", "OPTIONS"]),
    ("/api/notes",           notes_handler,          ["GET",  "POST", "OPTIONS"]),
    ("/api/appointment",     appointment_handler,    ["GET",  "POST", "OPTIONS"]),
    ("/api/tasks",           tasks_handler,          ["GET",  "POST", "OPTIONS"]),
    ("/api/doctorprofile",   doctorprofile_handler,  ["GET",  "OPTIONS"]),
    ("/api/patientprofile",  patientprofile_handler, ["GET",  "OPTIONS"]),
    ("/api/auditlogs",       auditlogs_handler,      ["GET",  "OPTIONS"]),
    ("/api/ping",            ping_handler,           ["GET",  "OPTIONS"]),
]

for path, fn, methods in ROUTES:
    endpoint = path.lstrip("/").replace("/", "_")
    app.add_url_rule(path, endpoint=endpoint,
                     view_func=make_route(fn, endpoint), methods=methods)

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
