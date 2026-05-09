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
