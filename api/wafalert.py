"""
api/wafalert.py — WAF Alert Receiver

ModSecurity (in nginx) detects SQL injection and sets an env variable.
nginx then makes a subrequest to /api/waf-alert, which this handler
catches and writes directly into monitor.threat_actors.

This way the WAF populates the SIEM table autonomously — no Flask
business logic needs to scan requests itself.

Flow:
  Attacker sends SQLi  →  ModSecurity blocks (403)  →  nginx internal
  redirect to /api/waf-alert  →  this handler writes to DB  →  attacker
  IP appears in Admin panel under Threat Actors automatically.
"""
import json, logging, os
from api.common import (
    SessionLocal, ThreatActor, ForensicLedger, SecurityAlert,
    get_client_ip, _headers, run_async
)

log = logging.getLogger(__name__)

# nginx passes the ModSecurity alert via a custom header it sets internally.
# The header format is: X-Modsec-Alert: <RULE_TAG>|<ATTACKER_IP>
# e.g.  X-Modsec-Alert: SQLi_UNION|203.0.113.45
WAF_SECRET_HEADER = os.environ.get("WAF_INTERNAL_SECRET", "phantasm-waf-internal")


async def _run(alert_header: str, nginx_ip: str, request_uri: str, ua: str):
    """Parse the WAF alert and write to monitor schema."""
    # Validate this came from our nginx (not a spoofed external request)
    if not alert_header:
        return 400, {"detail": "No WAF alert data."}

    # Parse "RULE_TAG|ATTACKER_IP" from the header
    parts = alert_header.split("|", 1)
    rule_tag   = parts[0].strip() if parts else "UNKNOWN"
    # Prefer the IP nginx extracted from the real request over the subrequest IP
    attacker_ip = parts[1].strip() if len(parts) > 1 else nginx_ip

    reason = (
        f"WAF_BLOCK | rule={rule_tag} | uri={request_uri[:120]} | "
        f"ua={ua[:80]}"
    )

    async with SessionLocal() as db:
        try:
            # Write to monitor.threat_actors
            ta = ThreatActor(
                ip_address=attacker_ip,
                reason=reason,
                threat_level="high" if "SQLi" in rule_tag else "medium",
            )
            db.add(ta)
            await db.flush()

            # Write to monitor.forensic_ledger
            db.add(ForensicLedger(
                threat_id=ta.threat_id,
                action_type=f"WAF_BLOCK_{rule_tag}",
                target_table="nginx.modsecurity",
                query_text=json.dumps({
                    "waf_rule":     rule_tag,
                    "attacker_ip":  attacker_ip,
                    "request_uri":  request_uri[:200],
                    "user_agent":   ua[:120],
                    "source":       "ModSecurity WAF",
                    "note": (
                        "Blocked by ModSecurity before reaching Flask backend. "
                        "IP auto-logged by WAF rule without Flask involvement."
                    ),
                }),
            ))

            # Raise a security alert so it shows in admin panel
            db.add(SecurityAlert(
                threat_id=ta.threat_id,
                alert_title=f"WAF: {rule_tag} Attack Blocked",
                description=(
                    f"ModSecurity blocked a {rule_tag} attack from {attacker_ip}. "
                    f"Request URI: {request_uri[:100]}. "
                    f"IP has been auto-flagged in Threat Actors."
                ),
                is_resolved=False,
            ))

            await db.commit()
            log.warning(
                "WAF alert logged: rule=%s ip=%s uri=%s",
                rule_tag, attacker_ip, request_uri[:80],
            )
            return 200, {"logged": True, "rule": rule_tag, "ip": attacker_ip}

        except Exception as e:
            log.error("WAF alert DB write failed: %s", e)
            try:
                await db.rollback()
            except Exception:
                pass
            return 500, {"detail": "DB write failed."}


def handler(request, context=None):
    from flask import request as flask_req

    if request.method == "OPTIONS":
        return {"statusCode": 204, "headers": _headers("POST, GET, OPTIONS"), "body": ""}

    headers = request.headers or {}

    # Security check — only accept from nginx (internal subrequest)
    internal_secret = headers.get("X-Waf-Internal", "")
    if internal_secret != WAF_SECRET_HEADER:
        # Silently return 200 to avoid leaking info; just don't process it
        return {"statusCode": 200, "headers": _headers("POST, GET, OPTIONS"),
                "body": json.dumps({"ok": True})}

    alert_header = headers.get("X-Modsec-Alert", "")
    nginx_ip     = get_client_ip(request)
    request_uri  = headers.get("X-Original-Uri", "")
    ua           = headers.get("User-Agent", "")

    status, data = run_async(_run(alert_header, nginx_ip, request_uri, ua))
    return {
        "statusCode": status,
        "headers": _headers("POST, GET, OPTIONS"),
        "body": json.dumps(data),
    }
