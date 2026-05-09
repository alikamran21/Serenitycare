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
    if not check_rate_limit(ip):
        return 429, {"detail": "Too many requests. Please wait."}

    raw_id    = str(body.get("user_id", "")).strip()
    password  = str(body.get("password", "")).strip()
    role_hint = str(body.get("role", "")).strip().lower()
    
    if not raw_id:
        return 400, {"detail": "Please enter your ID."}

    # Check both the ID and the Password fields for attacks
    attack = scan_for_attacks(raw_id) or scan_for_attacks(password)

    async with SessionLocal() as db:
        
        # --- START OF HONEYPOT BYPASS FIX ---
        # If an attack is detected, log it and instantly return a honeypot JWT.
        # This completely skips the OTP creation and verification steps.
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
