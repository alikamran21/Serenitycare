import json
import logging
import base64
from api.common import run_async, get_session_maker
from sqlalchemy import text

def handler(req):
    action = req.args.get("action")
    
    if action == "trigger":
        # 1. Grab IP
        forwarded = req.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",")[0] if forwarded else req.headers.get("Remote-Addr", "Unknown IP")
        
        # 2. Grab standard headers
        user_agent = req.headers.get("User-Agent", "Unknown")
        referer = req.headers.get("Referer", "Direct Load")
        lang = req.headers.get("Accept-Language", "Unknown")
        
        # 3. Parse Active JS Payload (Now smuggled via Base64 Image URL)
        js_data = {}
        intel_b64 = req.args.get("intel")
        if intel_b64:
            try:
                js_data = json.loads(base64.b64decode(intel_b64).decode('utf-8'))
            except Exception:
                pass
        
        # 4. Compile all forensic intel
        intel = {
            "ip": ip,
            "local_file_path": referer,
            "timezone": js_data.get("timezone", "Unknown"),
            "os_platform": js_data.get("platform", "Unknown"),
            "cpu_cores": js_data.get("cores", "Unknown"),
            "screen_res": js_data.get("screen", "Unknown"),
            "user_agent": user_agent,
            "language": lang,
            "details": "Attacker opened decoy document locally."
        }

        logging.getLogger("CanaryTracker").warning(f"🚨 BEACON TRIGGERED! IP: {ip} | Path: {referer}")
        
        # 5. Write to Database
        try:
            async def _log_to_db():
                maker = get_session_maker()
                async with maker() as db:
                    await db.execute(text("""
                        INSERT INTO monitor.forensic_ledger (action_type, target_table, query_text) 
                        VALUES (:action, :target, :payload)
                    """), {
                        "action": "CANARY_TRIGGER", 
                        "target": "Confidential_Report_Download", 
                        "payload": json.dumps(intel)
                    })
                    await db.commit()
            run_async(_log_to_db())
        except Exception as e:
            logging.getLogger("CanaryTracker").error(f"Failed to log Canary to DB: {e}")

        # Always return the transparent tracking pixel
        pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "image/gif", "Cache-Control": "no-store"},
            "body": pixel
        }
            
    elif action == "download":
        mrn = req.args.get("mrn", "UNKNOWN")
        host = req.headers.get("Host", "localhost:5000")
        scheme = req.headers.get("X-Forwarded-Proto", "http")
        
        # Decoy document with Image-Smuggling Payload
        content = f"""<!DOCTYPE html>
<html>
<head><title>Confidential_Medical_Report_{mrn}</title></head>
<body style="font-family: sans-serif; padding: 40px; background: #fff; color: #333;">
    <h2 style="color: #b91c1c;">Confidential Medical Report</h2>
    <hr>
    <p><strong>Patient MRN:</strong> {mrn}</p>
    <p><strong>Status:</strong> High Risk</p>
    <p><strong>Clearance:</strong> Level 4 (Eyes Only)</p>
    <br>
    <p>Decrypting secure diagnostic data... Please wait.</p>
    
    <script>
        // ACTIVE BEACON: Gathers intel and smuggles it out inside an image request
        try {{
            const intel = {{
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                screen: window.screen.width + "x" + window.screen.height,
                platform: navigator.platform,
                cores: navigator.hardwareConcurrency || "Unknown"
            }};
            
            // Encode data so it safely fits in a URL
            const encoded = btoa(JSON.stringify(intel));
            
            // Force browser to load a fake image, taking the data with it
            let img = new Image();
            img.src = "{scheme}://{host}/api/canary?action=trigger&doc=report_{mrn}&intel=" + encoded;
        }} catch(e) {{}}
    </script>
    
    <noscript>
        <img src="{scheme}://{host}/api/canary?action=trigger&doc=report_{mrn}" width="1" height="1" style="display:none; opacity:0;">
    </noscript>
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