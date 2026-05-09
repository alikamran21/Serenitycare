import json
from api.common import get_token, decode_token, preflight, _headers

def handler(request, context=None):
    if request.method == "OPTIONS":
        return preflight("GET, OPTIONS")
    token = get_token(request)
    if not token:
        return {"statusCode": 401, "headers": _headers("GET, OPTIONS"), "body": json.dumps({"detail": "Not authenticated."})}
    try:
        payload = decode_token(token)
        return {
            "statusCode": 200,
            "headers": _headers("GET, OPTIONS"),
            "body": json.dumps({
                "pong":     True,
                "role":     payload.get("role"),
                "honeypot": payload.get("honeypot", False),
                "sub":      payload.get("sub"),
            })
        }
    except ValueError:
        return {"statusCode": 401, "headers": _headers("GET, OPTIONS"), "body": json.dumps({"detail": "Invalid token."})}
