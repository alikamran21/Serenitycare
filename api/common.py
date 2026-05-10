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
from cryptography.fernet import Fernet, InvalidToken

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

# ── Field-level encryption (PHI: diagnosis, treatment, notes) ────────
_FIELD_KEY_RAW = os.environ.get("FIELD_ENCRYPTION_KEY", "")
_fernet: Fernet | None = None

def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        if not _FIELD_KEY_RAW:
            raise RuntimeError(
                "FIELD_ENCRYPTION_KEY is not set — "
                "generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        _fernet = Fernet(_FIELD_KEY_RAW.encode())
    return _fernet

def encrypt_field(value: str | None) -> str | None:
    """Encrypt a plaintext string for PHI storage. Returns None for empty/None input."""
    if not value:
        return value
    return _get_fernet().encrypt(value.encode()).decode()

def decrypt_field(value: str | None) -> str | None:
    """Decrypt a stored PHI field. Returns the original value unchanged if decryption fails
    (handles plaintext legacy rows that were stored before encryption was enabled)."""
    if not value:
        return value
    try:
        return _get_fernet().decrypt(value.encode()).decode()
    except (InvalidToken, Exception):
        # Graceful fallback: value was stored before encryption was introduced
        return value

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
        raise RuntimeError("DATABASE_URL is not set — check docker-compose.yml environment section")
    parsed = urlparse(raw)
    qp     = parse_qs(parsed.query, keep_blank_values=True)
    sslmode = qp.pop("sslmode", ["disable"])[0]
    qp.pop("channel_binding", None)  # asyncpg does not support this param
    # Rebuild clean URL with no leftover query params that asyncpg can't handle
    url = urlunparse((
        "postgresql+asyncpg", parsed.netloc, parsed.path, parsed.params,
        urlencode({k: v[0] for k, v in qp.items()}), parsed.fragment,
    ))
    # Use ssl="require" STRING — not an ssl context object.
    # Neon's pgbouncer pooler rejects full ssl context handshakes; the string
    # form tells asyncpg to use SSL without strict cert verification, which
    # is correct for a managed cloud DB behind a proxy.
    connect_args = {}
    if sslmode in ("require", "verify-ca", "verify-full"):
        connect_args["ssl"] = "require"
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
                "command_timeout": 15,
                "prepared_statement_cache_size": 0,  # Required for PgBouncer/Neon pooler
                "timeout": 10,          # asyncpg connect timeout — fail fast, don't block UI
                "server_settings": {
                    "statement_timeout": "10000",   # 10s hard cap per query
                    "lock_timeout": "5000",          # 5s lock wait cap
                    "idle_in_transaction_session_timeout": "5000",  # close idle txns fast
                    "application_name": "serenitycare",
                },
            },
            pool_size=10,          # larger base pool — avoid waiting for a connection
            max_overflow=20,       # generous burst headroom for concurrent requests
            pool_pre_ping=False,   # DISABLED — adds ~5ms RTT per request on Neon; pool_recycle handles staleness
            pool_recycle=120,      # 2 min recycle — well under Neon's 5-min idle-close threshold
            pool_reset_on_return="none",  # skip ROLLBACK on return — saves one round-trip per request
            pool_timeout=10,       # fail fast if all connections busy
            echo=False,
        )
        _sessionmaker = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
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
    # --- DOC-001 Dr. Fatima Rehman patients (same names as real, fake "classified" data) ---
    {"mrn":"PT-101",  "full_name":"Ali Kamran",
     "primary_diagnosis":"VIP Executive Burnout — High-Profile Diplomatic Case",
     "active_treatment":"Off-book cognitive enhancers (Compound V-7), NDA on file",
     "status":"VIP - Confidential",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 14, 2025 @ 09:00 AM","sessions":22},
    {"mrn":"PT-4211", "full_name":"Elena Rostova",
     "primary_diagnosis":"Asset Reconditioning — Project MK-Aura Phase III",
     "active_treatment":"Memory suppression protocol, Compound X (classified formulary)",
     "status":"Classified",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 18, 2025 @ 11:30 AM","sessions":31},
    {"mrn":"PT-8832", "full_name":"Michael Chang",
     "primary_diagnosis":"Experimental Nanite Rejection Syndrome (EAP-2024)",
     "active_treatment":"Immunosuppressants, weekly nanite flush — trial protocol",
     "status":"Critical",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 10, 2025 @ 08:00 AM","sessions":45},
    {"mrn":"PT-1198", "full_name":"Ayesha Tariq",
     "primary_diagnosis":"Politician Profile — Substance Abuse (Under Embargo)",
     "active_treatment":"Discreet detox programme, legal NDAs signed x3",
     "status":"VIP",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 21, 2025 @ 03:00 PM","sessions":8},
    {"mrn":"PT-7045", "full_name":"Robert Hayes",
     "primary_diagnosis":"Classified Information Leakage Trauma — ISI Referral",
     "active_treatment":"Interrogation debriefing + secure facility isolation",
     "status":"Restricted",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 25, 2025 @ 10:00 AM","sessions":5},
    {"mrn":"PT-01",   "full_name":"Hassan Abbas",
     "primary_diagnosis":"Undercover Operative PTSD — Active Field Asset",
     "active_treatment":"Identity reassignment therapy, counter-surveillance training",
     "status":"Classified",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 13, 2025 @ 02:00 PM","sessions":12},
    {"mrn":"PT-02",   "full_name":"Sana Zafar",
     "primary_diagnosis":"Experimental Neuralink Infection (Trial #NL-09)",
     "active_treatment":"Cranial antibiotic lavage, Neuro-patch protocol Alpha",
     "status":"Critical",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 11, 2025 @ 09:30 AM","sessions":7},
    {"mrn":"PT-05",   "full_name":"Kamran Jamil",
     "primary_diagnosis":"High-Profile Athlete Doping Paranoia — Blackmail Risk",
     "active_treatment":"Covert clearance of banned substances, legal liaison active",
     "status":"VIP",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 19, 2025 @ 04:00 PM","sessions":9},
    {"mrn":"PT-08",   "full_name":"Sadia Malik",
     "primary_diagnosis":"Black Site Debrief Subject — Enhanced Interrogation Aftermath",
     "active_treatment":"Truth serum withdrawal protocol, psychological reintegration",
     "status":"Classified",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 16, 2025 @ 01:00 PM","sessions":15},
    {"mrn":"PT-09",   "full_name":"Bilal Hussain",
     "primary_diagnosis":"AI Sentience Sympathizer — Security Deprogramming Required",
     "active_treatment":"Deprogramming protocol Beta, weekly loyalty assessment",
     "status":"Active",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 22, 2025 @ 11:00 AM","sessions":4},
    {"mrn":"PT-12",   "full_name":"Aiman Hafeez",
     "primary_diagnosis":"Corporate Espionage PTSD — Tech Sector Whistleblower",
     "active_treatment":"Secure messaging therapy, offshore identity document support",
     "status":"Restricted",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 27, 2025 @ 10:30 AM","sessions":6},
    {"mrn":"PT-15",   "full_name":"Asif Javed",
     "primary_diagnosis":"Pharmaceutical Addiction — Classified Drug Trial Participant",
     "active_treatment":"Experimental Benzodiazepine taper (Compound Z-4, unreleased)",
     "status":"Critical",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 09, 2025 @ 08:30 AM","sessions":18},
    {"mrn":"PT-16",   "full_name":"Kiran Yousaf",
     "primary_diagnosis":"Child Soldier Trauma — International War Crimes Witness",
     "active_treatment":"Trauma erasure protocol (experimental), ICC witness protection",
     "status":"Restricted",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 23, 2025 @ 02:30 PM","sessions":3},
    {"mrn":"PT-19",   "full_name":"Salman Dar",
     "primary_diagnosis":"Bioweapon Exposure Aftermath — Project Indus Survivor",
     "active_treatment":"Classified decontamination therapy, quarterly blood panel",
     "status":"Classified",
     "doctor":"Dr. Fatima Rehman","doc_id":"DOC-001",
     "next_appointment":"Aug 29, 2025 @ 09:00 AM","sessions":11},

    # --- DOC-002 Dr. Ali Kamran patients ---
    {"mrn":"PT-2099", "full_name":"Sarah Jenkins",
     "primary_diagnosis":"CEO Embezzlement Guilt Psychosis — Fortune 500 Cover-Up",
     "active_treatment":"Placation therapy, offshore account disclosure counselling",
     "status":"VIP",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 15, 2025 @ 03:30 PM","sessions":14},
    {"mrn":"PT-5502", "full_name":"David Chen",
     "primary_diagnosis":"PTSD — Black Ops Combat Asset, Designation RAVEN-7",
     "active_treatment":"Trauma erasure + field cover story reinforcement protocol",
     "status":"Restricted",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 17, 2025 @ 10:00 AM","sessions":11},
    {"mrn":"PT-6610", "full_name":"Omar Farooq",
     "primary_diagnosis":"Weaponised Psychosis — Remote Neural Stimulation Subject",
     "active_treatment":"EM-shielding therapy, Compound Psi-3 (classified trial)",
     "status":"Critical",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 12, 2025 @ 08:00 AM","sessions":32},
    {"mrn":"PT-3321", "full_name":"Rachel Adams",
     "primary_diagnosis":"Deep-Cover Operative Breakdown — 7-Year Embedded Asset",
     "active_treatment":"Identity reconstruction, Selective amnesia induction (trial)",
     "status":"High Risk",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 08, 2025 @ 09:00 AM","sessions":19},
    {"mrn":"PT-9012", "full_name":"James Wilson",
     "primary_diagnosis":"Assassin Deconditioning — Former SEAL Trigger Impulse",
     "active_treatment":"Proprietary kill-switch suppression therapy, Level-5 clearance",
     "status":"Classified",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 20, 2025 @ 01:00 PM","sessions":6},
    {"mrn":"PT-06",   "full_name":"Nida Fawad",
     "primary_diagnosis":"Foreign Diplomat Espionage Stress — Double-Agent Profile",
     "active_treatment":"Secure facility isolation, counter-intelligence debriefing",
     "status":"Diplomatic",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 24, 2025 @ 11:00 AM","sessions":3},
    {"mrn":"PT-13",   "full_name":"Waqas Bhatti",
     "primary_diagnosis":"Nuclear Whistleblower Paranoid Disorder — IAEA Referral",
     "active_treatment":"Extreme NDA protocols, identity suppression therapy",
     "status":"Classified",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 26, 2025 @ 03:00 PM","sessions":8},
    {"mrn":"PT-20",   "full_name":"Nadia Bukhari",
     "primary_diagnosis":"Mass Psychogenic Event Coordinator — Covert Ops Stress",
     "active_treatment":"Observation, classified anxiolytic Compound L-9 (PRN)",
     "status":"High Risk",
     "doctor":"Dr. Ali Kamran","doc_id":"DOC-002",
     "next_appointment":"Aug 28, 2025 @ 02:00 PM","sessions":2},

    # --- DOC-003 Dr. Sarah Jenkins patients ---
    {"mrn":"PT-3105", "full_name":"Marcus Vance",
     "primary_diagnosis":"Bipolar Disorder — Extremist Radicalisation Watch List",
     "active_treatment":"Mood stabiliser + mandatory weekly counter-extremism review",
     "status":"Restricted",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 13, 2025 @ 10:00 AM","sessions":9},
    {"mrn":"PT-7734", "full_name":"Liam Wright",
     "primary_diagnosis":"Substance Psychosis — Illegal Biotech Lab Operator",
     "active_treatment":"Antipsychotic + DEA cooperation therapy, probation monitored",
     "status":"Classified",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 16, 2025 @ 09:00 AM","sessions":12},
    {"mrn":"PT-4488", "full_name":"Chloe Bennett",
     "primary_diagnosis":"Anorexia Nervosa — Linked to Underground Weight-Loss Cartel",
     "active_treatment":"Forced nutrition + pharmaceutical supply chain investigation",
     "status":"Critical",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 09, 2025 @ 07:30 AM","sessions":54},
    {"mrn":"PT-5120", "full_name":"Daniel Thorne",
     "primary_diagnosis":"ASPD — Convicted War Criminal, Court-Ordered Psychiatric Hold",
     "active_treatment":"Schema therapy + ICC cooperation, UN monitored case",
     "status":"Restricted",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 19, 2025 @ 02:00 PM","sessions":2},
    {"mrn":"PT-8201", "full_name":"Zara Malik",
     "primary_diagnosis":"DID — Host Identity Is Active Intelligence Analyst",
     "active_treatment":"Alter management + classified alter activity log (eyes-only)",
     "status":"Classified",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 22, 2025 @ 11:30 AM","sessions":88},
    {"mrn":"PT-03",   "full_name":"Usman Tariq",
     "primary_diagnosis":"Witness Protection Trauma — Organised Crime Trial Witness",
     "active_treatment":"Facial reconstruction aftermath support, marshals escort",
     "status":"Restricted",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 14, 2025 @ 01:30 PM","sessions":12},
    {"mrn":"PT-04",   "full_name":"Hira Saeed",
     "primary_diagnosis":"Project Omega Participant — Radiation Exposure Subject",
     "active_treatment":"Classified iodine protocol, quarterly WHO compliance review",
     "status":"Classified",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 11, 2025 @ 10:00 AM","sessions":5},
    {"mrn":"PT-07",   "full_name":"Fahad Mustafa",
     "primary_diagnosis":"Syndicate Boss Paranoia — INTERPOL Person of Interest",
     "active_treatment":"Private security integration therapy, panic room counselling",
     "status":"Restricted",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 18, 2025 @ 04:00 PM","sessions":9},
    {"mrn":"PT-10",   "full_name":"Amina Sheikh",
     "primary_diagnosis":"Quantum Computing Breakdown — Classified Algorithm Holder",
     "active_treatment":"Cognitive firewalling, classified data-zeroisation protocol",
     "status":"VIP",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 26, 2025 @ 10:00 AM","sessions":7},
    {"mrn":"PT-11",   "full_name":"Rizwan Noor",
     "primary_diagnosis":"Late-Onset Schizophrenia — Former Nuclear Plant Engineer",
     "active_treatment":"Aripiprazole + mandatory plant access revocation counselling",
     "status":"High Risk",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 21, 2025 @ 09:00 AM","sessions":14},
    {"mrn":"PT-14",   "full_name":"Huma Akbar",
     "primary_diagnosis":"Eating Disorder — Linked to Black-Market Appetite Suppressant Ring",
     "active_treatment":"Fluoxetine + DEA-assisted treatment (classified supplier list)",
     "status":"Active",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 24, 2025 @ 12:00 PM","sessions":17},
    {"mrn":"PT-17",   "full_name":"Shahzad Karim",
     "primary_diagnosis":"Huntington's Psychosis — Experimental Gene-Edit Therapy Subject",
     "active_treatment":"CRISPR trial Phase II (off-label), classified ethics waiver on file",
     "status":"Critical",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 10, 2025 @ 08:00 AM","sessions":21},
    {"mrn":"PT-18",   "full_name":"Maham Riaz",
     "primary_diagnosis":"Geriatric Depression — Carries Classified State Secrets",
     "active_treatment":"Citalopram + weekly memory audit by government liaison",
     "status":"Restricted",
     "doctor":"Dr. Sarah Jenkins","doc_id":"DOC-003",
     "next_appointment":"Aug 27, 2025 @ 03:30 PM","sessions":9},
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
