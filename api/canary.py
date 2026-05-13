import json
import logging
from api.common import run_async, get_session_maker
from sqlalchemy import text

def handler(req):
    action = req.args.get("action")
    
    if action == "trigger":
        # Attacker opened the file - log their real IP
        forwarded = req.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",")[0] if forwarded else req.headers.get("Remote-Addr", "Unknown IP")
        
        logging.getLogger("CanaryTracker").warning(f"🚨 CANARY BEACON TRIGGERED! True IP revealed: {ip}")
        
        # --- Write to monitor.forensic_ledger so it shows in the Admin Interface ---
        try:
            async def _log_to_db():
                maker = get_session_maker()
                async with maker() as db:
                    # Format as JSON so api/auditlogs.py can parse the "ip" key perfectly
                    payload = json.dumps({
                        "ip": ip,
                        "details": "Attacker opened decoy document locally on their machine."
                    })
                    
                    await db.execute(text("""
                        INSERT INTO monitor.forensic_ledger (action_type, target_table, query_text) 
                        VALUES (:action, :target, :payload)
                    """), {
                        "action": "CANARY_TRIGGER", 
                        "target": "Confidential_Report_Download", 
                        "payload": payload
                    })
                    await db.commit()
            run_async(_log_to_db())
        except Exception as e:
            logging.getLogger("CanaryTracker").error(f"Failed to log Canary to DB: {e}")
        # -----------------------------------------------------------------

        # Transparent 1x1 GIF tracking pixel
        pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "image/gif",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
            },
            "body": pixel
        }
        
    elif action == "download":
        mrn = req.args.get("mrn", "UNKNOWN")
        host = req.headers.get("Host", "localhost:5000")
        scheme = req.headers.get("X-Forwarded-Proto", "http")
        
        # Decoy document containing the tracking pixel. 
        content = f"""<!DOCTYPE html>
<html>
<head><title>Confidential_Medical_Report_{mrn}</title></head>
<body style="font-family: sans-serif; padding: 40px;">
    <h2 style="color: #b91c1c;">Confidential Medical Report</h2>
    <hr>
    <p><strong>Patient MRN:</strong> {mrn}</p>
    <p><strong>Status:</strong> High Risk</p>
    <p>Loading secure diagnostic data...</p>
    
    <img src="{scheme}://{host}/api/canary?action=trigger&doc=report_{mrn}" width="1" height="1" style="display:none; opacity:0;">
</body>
</html>"""
        
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "text/html",
                "Content-Disposition": f'attachment; filename="Confidential_Report_{mrn}.html"'
            },
            "body": content
        }
        
    return {"statusCode": 400, "body": json.dumps({"error": "Invalid action"})}