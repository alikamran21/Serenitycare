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
                "command_timeout": 10,
                "prepared_statement_cache_size": 0,
                "statement_cache_size": 0,
                "timeout": 10,          # asyncpg connect timeout
                "server_settings": {
                    "statement_timeout": "8000",
                },
            },
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=False,        # Disabled: saves a round-trip on every checkout
            pool_recycle=300,           # 5 min recycle keeps Neon connections fresh
            pool_timeout=15,
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
