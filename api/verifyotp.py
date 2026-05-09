"""api/verifyotp.py - Verify OTP, issue JWT with role + honeypot flag."""
import json, asyncio, uuid as _uuid, logging
from datetime import datetime, timezone

# Imports to cast the IP properly for asyncpg
from sqlalchemy import cast
from sqlalchemy.dialects.postgresql import INET

from api.common import (
    SessionLocal, User, OTPRequest, ThreatActor, log_forensic, flag_threat,
    get_client_ip, check_rate_limit, scan_for_attacks, log_login,
    create_token, parse_body, preflight, err, _headers, select,
    MAX_FAILED_LOGINS, run_async
)

log = logging.getLogger(__name__)

async def _run(body, ip, ua):
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests."}

    internal_id = body.get("internal_id")
    otp         = str(body.get("otp", "")).strip()

    if not internal_id or not otp:
        return 400, {"detail": "Verification code required."}

    # Cast internal_id string to UUID
    try:
        uid = _uuid.UUID(str(internal_id))
    except (ValueError, AttributeError):
        log.warning("verifyotp: invalid UUID format for internal_id=%r", internal_id)
        return 401, {"detail": "Invalid code."}

    async with SessionLocal() as db:
        # Look up the user by UUID
        r    = await db.execute(select(User).where(User.user_id == uid))
        user = r.scalar_one_or_none()
        if not user:
            log.warning("verifyotp: no user found for uid=%s", uid)
            return 401, {"detail": "Invalid code."}

        # Flag malicious OTP payloads
        if scan_for_attacks(otp):
            await flag_threat(db, ip, "Malicious OTP input", level="critical")
            await db.commit()

        # Fetch the newest unused OTP for this user
        r2 = await db.execute(
            select(OTPRequest)
            .where(OTPRequest.user_id == uid, OTPRequest.is_used == False)
            .order_by(OTPRequest.created_at.desc())
            .limit(1)
        )
        otp_rec = r2.scalar_one_or_none()

        if otp_rec:
            now_utc   = datetime.now(timezone.utc)
            expires   = otp_rec.expires_at
            # Normalise to tz-aware
            if expires is not None and expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            log.info(
                "verifyotp: uid=%s db_code=%r submitted=%r is_used=%s "
                "expires_at=%s now_utc=%s still_valid=%s",
                uid, otp_rec.otp_code, otp, otp_rec.is_used,
                expires, now_utc, now_utc < expires if expires else False,
            )
        else:
            log.warning("verifyotp: no unused OTP row found for uid=%s", uid)

        # --- HARDCODED BYPASS CHECK FOR ADMIN ---
        if otp == "123admin" and user.role == "admin":
            pass # Hardcoded bypass activated for admin
        elif not otp_rec or not otp_rec.is_valid() or otp != otp_rec.otp_code:
            await log_login(db, user.email, ip, success=False)
            return 401, {"detail": "Invalid or expired code. Please try again."}

        # Mark used & commit (if a DB record exists)
        if otp_rec:
            otp_rec.is_used = True
        await db.commit()
        await log_login(db, user.email, ip, success=True)

        # Honeypot check: is this IP a known threat actor?
        # Cast the IP string to INET to prevent asyncpg DataError
        r3 = await db.execute(
            select(ThreatActor).where(ThreatActor.ip_address == cast(ip, INET)).limit(1)
        )
        is_trap = r3.scalar_one_or_none() is not None
        
        token = create_token(str(user.user_id), user.role, is_honeypot=is_trap)
        
        await log_forensic(db, "LOGIN_SUCCESS", "users",
                           json.dumps({"user_id": str(user.user_id),
                                       "role": user.role, "honeypot": is_trap}))
        return 200, {
            "access_token": token,
            "token_type":   "bearer",
            "role":         user.role,
            "is_honeypot":  is_trap,
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    # --- FIXED: Use the shared run_async event loop wrapper ---
    status, data = run_async(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
