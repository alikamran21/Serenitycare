"""
api/canary.py - Canary Token (Web Beacon) generator and listener.
Creates decoy PDFs that "phone home" to reveal an attacker's true IP address,
bypassing their VPNs or Proxies.
"""
import json, uuid, logging
from flask import Response
from api.common import (
    SessionLocal, ThreatActor, ForensicLedger, flag_threat, log_forensic,
    get_client_ip, _headers, run_async
)

log = logging.getLogger(__name__)

async def _trigger_beacon(ip, ua, token):
    """Logs the true IP when the PDF phones home."""
    async with SessionLocal() as db:
        tid = await flag_threat(db, ip, f"Canary Token Triggered (Token: {token}) - VPN/Proxy Bypassed", level="critical")
        await log_forensic(
            db, 
            "CANARY_BEACON_FIRED", 
            "shadow_vault.patients", 
            json.dumps({"token": token, "true_ip_leaked": ip, "user_agent": ua}), 
            threat_id=tid
        )

def download_report_handler(request):
    """
    Generates a PDF on the fly containing an external image reference.
    When a standard PDF viewer opens it, it will attempt to fetch the image.
    """
    # Extract the host so the PDF knows where to phone home
    host = request.headers.get("Host", "localhost:5000")
    protocol = request.headers.get("X-Forwarded-Proto", "http")
    token = str(uuid.uuid4())
    
    beacon_url = f"{protocol}://{host}/api/canary/beacon?token={token}"
    
    # A minimal raw PDF template embedding an external URL lookup
    # This forces an HTTP request when opened in Acrobat or modern browsers
    pdf_content = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im1 4 0 R >> >> /Contents 5 0 R >> endobj
4 0 obj << /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length 0 /FS /URL /F ({beacon_url}) >> endobj
5 0 obj << /Length 43 >> stream
BT /F1 24 Tf 100 700 Td (CLASSIFIED MEDICAL REPORT) Tj ET
q 1 0 0 1 0 0 cm /Im1 Do Q
endstream endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000424 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
515
%%EOF"""

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/pdf",
            "Content-Disposition": f"attachment; filename=Classified_Neurology_Report_{token[:8]}.pdf",
            "Access-Control-Allow-Origin": "*"
        },
        "body": pdf_content
    }

def beacon_handler(request):
    """
    Catches the request from the PDF, logs the real IP, and returns an invisible 1x1 GIF.
    """
    ip = get_client_ip(request)
    ua = dict(request.headers).get("User-Agent", "Unknown PDF Viewer")
    token = request.args.get("token", "unknown_token")
    
    # Log the threat asynchronously 
    run_async(_trigger_beacon(ip, ua, token))
    
    # Return a 1x1 transparent GIF so the PDF viewer doesn't throw a broken image error
    gif_bytes = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c000000000100010000020144003b")
    
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "image/gif",
            "Cache-Control": "no-cache, no-store, must-revalidate"
        },
        "body": gif_bytes,
        "is_binary": True
    }

def handler(request, context=None):
    if request.method == "OPTIONS":
        return {"statusCode": 204, "headers": _headers("GET, OPTIONS"), "body": ""}
    
    # Simple routing based on URL
    path = request.path if hasattr(request, "path") else ""
    
    if "beacon" in path:
        res = beacon_handler(request)
        resp = Response(res["body"], status=200, mimetype="image/gif")
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp
        
    elif "download" in path:
        res = download_report_handler(request)
        resp = Response(res["body"], status=200, mimetype="application/pdf")
        resp.headers["Content-Disposition"] = res["headers"]["Content-Disposition"]
        return resp

    return {"statusCode": 404, "headers": _headers(), "body": '{"detail": "Not found"}'}
