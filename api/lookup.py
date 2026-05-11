"""api/lookup.py — ID-based OTP login (doctor_id / mrn). Tier 2 Controller."""
import json, asyncio, hashlib, uuid
from datetime import datetime, timedelta, timezone
from api.common import (
    SessionLocal, User, Doctor, Patient, OTPRequest,
    get_client_ip, check_rate_limit, scan_for_attacks,
    generate_otp, send_otp_email, mask_email, log_forensic, flag_threat,
    parse_body, preflight, err, _headers, select, OTP_EXPIRE, log, run_async,
    create_token
)

async def _run(body, ip, ua):
    raw_id    = str(body.get("user_id", "")).strip()
    password  = str(body.get("password", "")).strip()
    role_hint = str(body.get("role", "")).strip().lower()
    
    if not raw_id:
        return 400, {"detail": "Please enter your ID."}

    # Check both the ID and the Password fields for attacks
    attack = scan_for_attacks(raw_id) or scan_for_attacks(password)

    async with SessionLocal() as db:
        
        # FIXED: Rate Limit block moved inside SessionLocal to allow DB logging
        if not check_rate_limit(ip):
            tid = await flag_threat(db, ip, "Rate Limit Exceeded (lookup)", level="medium")
            await log_forensic(db, "RATE_LIMIT", "lookup", "Blocked by rate limiter", threat_id=tid)
            return 429, {"detail": "Too many requests. Please wait."}
            
        # --- START OF HONEYPOT BYPASS FIX ---
        if attack:
            try:
                category, snippet = attack
                tid = await flag_threat(db, ip, f"{category}: {snippet}", level="high")
                await log_forensic(db, f"ATTACK:{category}", "lookup", f"{raw_id} | {password}"[:80], threat_id=tid)
                await db.commit()
            except Exception as e:
                log.error("attack logging failed: %s", e)
                await db.rollback()
            
            # Determine role for the honeypot (default to patient if unknown to keep them sandboxed)
            trap_role = role_hint if role_hint in ["doctor", "patient", "admin"] else "patient"
            fake_uid = str(uuid.uuid4())
            
            # Issue trap token
            trap_token = create_token(fake_uid, trap_role, is_honeypot=True)
            
            # Return the final JWT payload directly
            return 200, {
                "access_token": trap_token,
                "token_type":   "bearer",
                "role":         trap_role,
                "is_honeypot":  True,
                "direct_login": True
            }
        # --- END OF HONEYPOT BYPASS FIX ---

        user = None

        # Look up by role hint or try both
        if role_hint == "admin":
            if raw_id in ("admin_root", "admin", "root", "admin@serenity.care"):
                r = await db.execute(select(User).where(User.email == 'admin@serenity.care'))
                user = r.scalar_one_or_none()
                
                if user and user.password_hash:
                    attempt_hash = hashlib.sha256(password.encode()).hexdigest()
                    if attempt_hash != user.password_hash:
                        return 401, {"detail": "Invalid passphrase. Access denied."}
                else:
                    return 401, {"detail": "Admin user not configured properly."}
            else:
                return 401, {"detail": "Invalid Admin ID."}

        elif role_hint == "doctor":
            r   = await db.execute(select(Doctor).where(Doctor.doc_id == raw_id))
            doc = r.scalar_one_or_none()
            if doc:
                r2   = await db.execute(select(User).where(User.user_id == doc.user_id))
                user = r2.scalar_one_or_none()
        elif role_hint == "patient":
            r   = await db.execute(select(Patient).where(Patient.mrn == raw_id))
            pat = r.scalar_one_or_none()
            if pat:
                r2   = await db.execute(select(User).where(User.user_id == pat.user_id))
                user = r2.scalar_one_or_none()
        else:
            # Try doctor first, then patient
            r = await db.execute(select(Doctor).where(Doctor.doc_id == raw_id))
            doc = r.scalar_one_or_none()
            if doc:
                r2 = await db.execute(select(User).where(User.user_id == doc.user_id))
                user = r2.scalar_one_or_none()
            if not user:
                r = await db.execute(select(Patient).where(Patient.mrn == raw_id))
                pat = r.scalar_one_or_none()
                if pat:
                    r2 = await db.execute(select(User).where(User.user_id == pat.user_id))
                    user = r2.scalar_one_or_none()

        if not user or not user.is_active:
            return 401, {"detail": "Invalid ID. Please check and try again."}

        # Insert OTP record 
        otp_code = generate_otp()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE)
        try:
            db.add(OTPRequest(
                user_id=user.user_id, otp_code=otp_code,
                expires_at=expires_at,
                created_ip=ip,
            ))
            await db.commit()
        except Exception as e:
            log.error("OTP insert failed: %s", e)
            await db.rollback()
            return 500, {"detail": "Internal error. Please try again."}

        # Send email
        try:
            send_otp_email(user.email, otp_code, user.email.split("@")[0])
        except Exception as e:
            log.error("Email send failed: %s", e)
            return 503, {"detail": f"Could not send verification email: {e}"}

        return 200, {
            "detail":       "Verification code sent to your registered device.",
            "masked_email": mask_email(user.email),
            "internal_id":  str(user.user_id),
        }

def handler(request, context=None):
    if request.method == "OPTIONS": return preflight()
    if request.method != "POST":    return err("Method not allowed.", 405)
    body = parse_body(request); ip = get_client_ip(request)
    ua   = (request.headers or {}).get("user-agent", "")
    status, data = run_async(_run(body, ip, ua))
    return {"statusCode": status, "headers": _headers(), "body": json.dumps(data)}
