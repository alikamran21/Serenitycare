"""
api/common.py — Shared utilities for Phantasm-DB (3-tier architecture).

Schema:
  public.users          → central auth (UUID PK)
  public.doctors        → doc_id (VARCHAR PK) + user_id FK
  public.patients       → mrn (VARCHAR PK) + user_id FK
  public.clinical_notes → note_id (UUID PK)
  public.appointments   → appt_id (UUID PK)
  public.daily_tasks    → task_id (UUID PK)
  public.otp_requests   → id (BIGSERIAL)
  monitor.* → SIEM tables (auto by triggers + backend)
  shadow_vault.* → honeypot mirrors
"""

import json, logging, os, random, re, ssl, string, time, hashlib, asyncio
import threading as _threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import resend

from jose import JWTError, jwt
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    String, Text, BigInteger, func, select, text
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import AsyncAdaptedQueuePool

log = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────────────────
JWT_SECRET    = os.environ.get("JWT_SECRET_KEY", "changeme")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE    = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 60))
OTP_EXPIRE    = int(os.environ.get("OTP_EXPIRE_MINUTES", 5))

RESEND_API_KEY  = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM     = os.environ.get("RESEND_FROM", "onboarding@resend.dev")
RESEND_FROM_NAME    = os.environ.get("SMTP_FROM_NAME", "Serenity Psychiatric Care")
TEST_EMAIL_OVERRIDE = os.environ.get("TEST_EMAIL_OVERRIDE", "")  # redirect all emails here during dev
RATE_LIMIT_MAX    = int(os.environ.get("RATE_LIMIT_REQUESTS", 30))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", 60))
MAX_FAILED_LOGINS = int(os.environ.get("MAX_FAILED_LOGINS", 5))

# ── Database ─────────────────────────────────────────────────────────
def _build_db_url():
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError("DATABASE_URL is not set")
    parsed = urlparse(raw)
    qp     = parse_qs(parsed.query, keep_blank_values=True)
    ssl_ok = qp.pop("sslmode", ["disable"])[0] in ("require","verify-ca","verify-full")
    qp.pop("channel_binding", None)
    url = urlunparse((
        "postgresql+asyncpg", parsed.netloc, parsed.path, parsed.params,
        urlencode({k: v[0] for k, v in qp.items()}), parsed.fragment,
    ))
    connect_args = {}
    if ssl_ok:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        connect_args["ssl"] = ctx
    return url, connect_args

_db_url, _db_connect_args = _build_db_url()

_engine = None
_sessionmaker = None

def get_session_maker():
    """Lazy initialization of the database engine inside the active event loop."""
    global _engine, _sessionmaker
    if _sessionmaker is None:
        _engine = create_async_engine(
            _db_url,
            poolclass=AsyncAdaptedQueuePool,
            connect_args={
                **_db_connect_args,
                "command_timeout": 30,
                "prepared_statement_cache_size": 0,  # Required for PgBouncer/Neon pooler
                "timeout": 30,          # asyncpg connect timeout (Neon cold starts can be slow)
                "server_settings": {
                    "statement_timeout": "25000",   # 25s — gives queries breathing room
                    "application_name": "serenitycare",
                },
            },
            pool_size=3,
            max_overflow=5,
            pool_pre_ping=True,         # Recycle stale Neon connections before use
            pool_recycle=180,           # 3 min recycle — Neon idle connections drop at 5 min
            pool_timeout=35,
            echo=False,
        )
        _sessionmaker = async_sessionmaker(
            bind=_engine, 
            class_=AsyncSession, 
            expire_on_commit=False, 
            autoflush=False, 
            autocommit=False
        )
    return _sessionmaker

def SessionLocal():
    """Drop-in replacement that generates a session from the lazy-loaded engine."""
    maker = get_session_maker()
    return maker()
# ── ORM Models (reflect the new schema) ─────────────────────────────
class Base(DeclarativeBase):
    pass

class User(Base):
    """public.users — central authentication table"""
    __tablename__ = "users"
    __table_args__ = {"schema": "public"}
    user_id       = Column(UUID(as_uuid=True), primary_key=True)
    email         = Column(String(255), unique=True, nullable=False)
    role          = Column(String(20), nullable=False)
    password_hash = Column(String(255), nullable=True) # NEW: Hashed credentials
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

class Doctor(Base):
    """public.doctors"""
    __tablename__ = "doctors"
    __table_args__ = {"schema": "public"}
    doc_id         = Column(String(20), primary_key=True)
    user_id        = Column(UUID(as_uuid=True), ForeignKey("public.users.user_id", ondelete="CASCADE"), unique=True)
    full_name      = Column(String(150))
    specialization = Column(String(150))

class Patient(Base):
    """public.patients"""
    __tablename__ = "patients"
    __table_args__ = {"schema": "public"}
    mrn               = Column(String(20), primary_key=True)
    user_id           = Column(UUID(as_uuid=True), ForeignKey("public.users.user_id", ondelete="CASCADE"), unique=True)
    doc_id            = Column(String(20), ForeignKey("public.doctors.doc_id"))
    full_name         = Column(String(150))
    primary_diagnosis = Column(Text)
    active_treatment  = Column(Text)
    status            = Column(String(50), default="Active")
    created_at        = Column(DateTime(timezone=True), server_default=func.now())

class ClinicalNote(Base):
    """public.clinical_notes"""
    __tablename__ = "clinical_notes"
    __table_args__ = {"schema": "public"}
    note_id    = Column(UUID(as_uuid=True), primary_key=True)
    mrn        = Column(String(20), ForeignKey("public.patients.mrn", ondelete="CASCADE"))
    doc_id     = Column(String(20), ForeignKey("public.doctors.doc_id"))
    notes_text = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Appointment(Base):
    """public.appointments"""
    __tablename__ = "appointments"
    __table_args__ = {"schema": "public"}
    appt_id      = Column(UUID(as_uuid=True), primary_key=True)
    mrn          = Column(String(20), ForeignKey("public.patients.mrn"))
    doc_id       = Column(String(20), ForeignKey("public.doctors.doc_id"))
    scheduled_at = Column(DateTime(timezone=True))
    is_urgent    = Column(Boolean, default=False)
    status       = Column(String(20), default="Scheduled")

class DailyTask(Base):
    """public.daily_tasks"""
    __tablename__ = "daily_tasks"
    __table_args__ = {"schema": "public"}
    task_id          = Column(UUID(as_uuid=True), primary_key=True)
    mrn              = Column(String(20), ForeignKey("public.patients.mrn"))
    task_title       = Column(Text)
    task_description = Column(Text)
    is_done          = Column(Boolean, default=False)
    updated_at       = Column(DateTime(timezone=True), server_default=func.now())

class OTPRequest(Base):
    """public.otp_requests"""
    __tablename__ = "otp_requests"
    __table_args__ = {"schema": "public"}
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id    = Column(UUID(as_uuid=True), ForeignKey("public.users.user_id", ondelete="CASCADE"))
    otp_code   = Column(String(6), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used    = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    created_ip = Column(INET)

    def is_valid(self):
        if self.is_used:
            return False
        expires = self.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires is not None and datetime.now(timezone.utc) < expires

class ForensicLedger(Base):
    """monitor.forensic_ledger"""
    __tablename__ = "forensic_ledger"
    __table_args__ = {"schema": "monitor"}
    ledger_id    = Column(BigInteger, primary_key=True, autoincrement=True)
    threat_id    = Column(BigInteger)
    action_type  = Column(Text)
    target_table = Column(Text)
    query_text   = Column(Text)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())

class SecurityAlert(Base):
    """monitor.security_alerts"""
    __tablename__ = "security_alerts"
    __table_args__ = {"schema": "monitor"}
    alert_id    = Column(BigInteger, primary_key=True, autoincrement=True)
    threat_id   = Column(BigInteger)
    alert_title = Column(Text)
    description = Column(Text)
    is_resolved = Column(Boolean, default=False)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())

class ThreatActor(Base):
    """monitor.threat_actors"""
    __tablename__ = "threat_actors"
    __table_args__ = {"schema": "monitor"}
    threat_id    = Column(BigInteger, primary_key=True, autoincrement=True)
    ip_address   = Column(INET)
    reason       = Column(Text)
    threat_level = Column(String(20), default="medium")
    flagged_at   = Column(DateTime(timezone=True), server_default=func.now())

class LoginActivity(Base):
    """monitor.login_activity"""
    __tablename__ = "login_activity"
    __table_args__ = {"schema": "monitor"}
    login_id        = Column(BigInteger, primary_key=True, autoincrement=True)
    email_attempted = Column(String(255))
    ip_address      = Column(INET)
    is_success      = Column(Boolean, default=False)
    attempt_time    = Column(DateTime(timezone=True), server_default=func.now())

# ── Security helpers ─────────────────────────────────────────────────
_ATTACK_PATTERNS = [
    ("SQL_INJECTION", [
        re.compile(r"(--|;|\/\*|\*\/)", re.I),
        re.compile(r"\b(union\s+select|select\s+.*\s+from)\b", re.I),
        re.compile(r"\b(drop|alter|truncate|exec|execute)\b", re.I),
        re.compile(r"(1\s*=\s*1|'\s*or\s*'1)", re.I),
    ]),
    ("XSS", [
        re.compile(r"<\s*script[\s>]", re.I),
        re.compile(r"javascript\s*:", re.I),
    ]),
    ("PATH_TRAVERSAL", [re.compile(r"\.\./")]),
    ("CMD_INJECTION", [re.compile(r"[;&|`]\s*(ls|cat|whoami|bash|sh)", re.I)]),
]

_rate_store: dict = defaultdict(deque)

def get_client_ip(request) -> str:
    hdrs = request.headers if hasattr(request, "headers") else {}
    xff  = hdrs.get("x-forwarded-for", hdrs.get("X-Forwarded-For", ""))
    return xff.split(",")[0].strip() if xff else "127.0.0.1"

def check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    dq  = _rate_store[ip]
    while dq and dq[0] < now - RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return False
    dq.append(now)
    return True

def scan_for_attacks(text: str):
    if not text:
        return None
    for category, patterns in _ATTACK_PATTERNS:
        for p in patterns:
            m = p.search(text)
            if m:
                return category, m.group(0)[:80]
    return None

async def flag_threat(db, ip: str, reason: str, level: str = "high"):
    try:
        ta = ThreatActor(ip_address=ip, reason=reason, threat_level=level)
        db.add(ta)
        await db.flush()
        return ta.threat_id
    except Exception as e:
        log.error("flag_threat error: %s", e)
        return None

async def log_forensic(db, action: str, table: str, payload: str, threat_id=None):
    try:
        db.add(ForensicLedger(threat_id=threat_id, action_type=action,
                               target_table=table, query_text=payload))
        await db.commit()
    except Exception as e:
        log.error("log_forensic error: %s", e)
        try: await db.rollback()
        except: pass

async def log_login(db, email: str, ip: str, success: bool):
    try:
        async with SessionLocal() as fresh_db:
            fresh_db.add(LoginActivity(email_attempted=email, ip_address=ip, is_success=success))
            await fresh_db.commit()
    except Exception as e:
        log.error("log_login error: %s", e)

# ── JWT ──────────────────────────────────────────────────────────────
def create_token(user_id: str, role: str, is_honeypot: bool = False) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "honeypot": is_honeypot,
         "exp": exp, "iat": datetime.now(timezone.utc)},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        raise ValueError("Invalid or expired token") from e

def generate_otp() -> str:
    return "".join(random.SystemRandom().choices(string.digits, k=6))

def mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        masked = local[0] + "*" * max(len(local)-2, 1) + (local[-1] if len(local)>2 else "")
        return f"{masked}@{domain}"
    except:
        return "****@****.***"

# ── Email ────────────────────────────────────────────────────────────
def send_otp_email(to: str, otp: str, name: str = "") -> None:
    greeting = f"Dear {name}," if name else "Hello,"
    html = f"""<html><body style="font-family:Arial,sans-serif;background:#f8fafc;">
      <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:12px;border:1px solid #e2e8f0;">
        <div style="background:#0f766e;padding:24px;text-align:center;border-radius:12px 12px 0 0;">
          <h1 style="color:#fff;margin:0;font-size:20px;">Serenity Psychiatric Care</h1>
        </div>
        <div style="padding:32px;">
          <p style="color:#334155;">{greeting}</p>
          <p style="color:#475569;">Your verification code:</p>
          <div style="background:#f0fdf4;border:2px solid #86efac;border-radius:8px;padding:16px;text-align:center;margin:16px 0;">
            <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#15803d;font-family:monospace;">{otp}</span>
          </div>
          <p style="color:#94a3b8;font-size:12px;">Expires in {OTP_EXPIRE} minutes. Do not share this code.</p>
        </div>
      </div>
    </body></html>"""
    actual_to = TEST_EMAIL_OVERRIDE if TEST_EMAIL_OVERRIDE else to
    resend.api_key = RESEND_API_KEY
    resend.Emails.send({
        "from":    f"{RESEND_FROM_NAME} <{RESEND_FROM}>",
        "to":      [actual_to],
        "subject": "Your Serenity Portal Verification Code",
        "html":    html,
    })
# ── HTTP helpers ─────────────────────────────────────────────────────
_ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGINS", "*").split(",")[0].strip()

def _headers(methods="POST, OPTIONS"):
    return {
        "Access-Control-Allow-Origin":  _ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": methods,
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Init-Secret",
        "Content-Type": "application/json",
    }

def ok(data, status=200, methods="POST, OPTIONS"):
    return {"statusCode": status, "headers": _headers(methods), "body": json.dumps(data)}

def err(detail, status=400, methods="POST, OPTIONS"):
    return {"statusCode": status, "headers": _headers(methods), "body": json.dumps({"detail": detail})}

def preflight(methods="POST, OPTIONS"):
    return {"statusCode": 204, "headers": _headers(methods), "body": ""}

def parse_body(request):
    try:
        raw = getattr(request, "body", b"") or b""
        if isinstance(raw, str): raw = raw.encode()
        return json.loads(raw) if raw else {}
    except:
        return {}

def get_token(request):
    hdrs = request.headers if hasattr(request, "headers") else {}
    auth = hdrs.get("Authorization", hdrs.get("authorization", ""))
    return auth[7:] if auth.startswith("Bearer ") else None

# ── Auth helpers ─────────────────────────────────────────────────────
async def get_user(token, db) -> tuple:
    if not token:
        return None, "Not authenticated."
    try:
        payload = decode_token(token)
    except ValueError as e:
        return None, str(e)
    uid = payload["sub"]
      # Honeypot tokens use a random fake UUID — skip DB lookup entirely.
    # Return a plain ghost object so all API handlers can proceed and
    # honeypot_gate will route them to shadow vault data.
    if payload.get("honeypot"):
        class _GhostUser:
            pass
        ghost            = _GhostUser()
        ghost.user_id    = uid
        ghost.email      = "honeypot@shadow.internal"
        ghost.role       = payload.get("role", "patient")
        ghost.is_active  = True
        ghost._is_honeypot = True
        return ghost, None

    result = await db.execute(select(User).where(User.user_id == uid))
    user   = result.scalar_one_or_none()
    if not user or not user.is_active:
        return None, "User not found."
    return user, None

async def is_flagged(db, user_id: str) -> bool:
    return False

async def honeypot_gate(db, user, ip: str, ua: str, action: str, table: str) -> bool:
    trap = getattr(user, "_is_honeypot", False)
    await log_forensic(db, action, table,
                       json.dumps({"ip": ip, "ua": ua[:80], "honeypot": trap}))
    return trap

def mark_honeypot(user, flag: bool):
    # Don't overwrite a flag already set (e.g. ghost user from get_user)
    if not getattr(user, "_is_honeypot", False):
        user._is_honeypot = flag

# ── Shadow (honeypot) data ───────────────────────────────────────────
SHADOW_PATIENTS = [
    {"mrn":"PT-9901","full_name":"Eleanor Voss",
     "primary_diagnosis":"Generalised Anxiety Disorder (F41.1)",
     "active_treatment":"Sertraline 50mg","status":"Stable",
     "doctor":"Dr. Fatima Rehman","next_appt":"2025-08-12 10:00"},
    {"mrn":"PT-9902","full_name":"Marcus Delray",
     "primary_diagnosis":"Major Depressive Disorder (F32.1)",
     "active_treatment":"Fluoxetine 20mg","status":"Improving",
     "doctor":"Dr. Ali Kamran","next_appt":"2025-08-15 14:30"},
    {"mrn":"PT-9903","full_name":"Priya Nair",
     "primary_diagnosis":"Bipolar II Disorder (F31.81)",
     "active_treatment":"Lamotrigine 100mg","status":"Stable",
     "doctor":"Dr. Sarah Jenkins","next_appt":"2025-08-20 09:00"},
]
SHADOW_DOCTOR = {"doc_id":"DOC-SHADOW-01","full_name":"Dr. Elias Thornton","specialization":"Psychiatry"}
SHADOW_PATIENT_SELF = SHADOW_PATIENTS[0]

# ── Shared async runner (Flask-safe) ────────────────────────────────
_loop: asyncio.AbstractEventLoop | None = None
_loop_lock = _threading.Lock()

def _run_loop(loop):
    """Explicitly set the loop for the background thread before running."""
    asyncio.set_event_loop(loop)
    loop.run_forever()

def _get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    if _loop is None or _loop.is_closed():
        with _loop_lock:
            if _loop is None or _loop.is_closed():
                _loop = asyncio.new_event_loop()
                t = _threading.Thread(
                    target=_run_loop, 
                    args=(_loop,), 
                    daemon=True, 
                    name="phantasm-async-loop"
                )
                t.start()
    return _loop

def run_async(coro):
    """Run a coroutine on the shared event loop from a sync Flask handler."""
    loop = _get_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=60)  # 60 s — allows for Neon cold-start wake-up
