# Nexora
This is our hacknex project

import os
import re
import time
import uuid
import hashlib
import secrets
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta

import bcrypt
import jwt
from cryptography.fernet import Fernet
from fastapi import Request, HTTPException, Depends
from motor.motor_asyncio import AsyncIOMotorClient

client = AsyncIOMotorClient(os.environ["MONGO_URL"])
db = client[os.environ["DB_NAME"]]
JWT_ALG = "HS256"
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage", "datasets")
os.makedirs(STORAGE_DIR, exist_ok=True)
_fernet = Fernet(os.environ["DATA_ENCRYPTION_KEY"].encode())


def now():
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def sha256(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def encrypt(b: bytes) -> bytes:
    return _fernet.encrypt(b)


def decrypt(b: bytes) -> bytes:
    return _fernet.decrypt(b)


def hash_password(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()


def verify_password(p, h):
    try:
        return bcrypt.checkpw(p.encode(), h.encode())
    except ValueError:
        return False


def make_token(user_id, kind, minutes):
    payload = {"sub": user_id, "type": kind, "jti": secrets.token_hex(8),
               "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes)}
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm=JWT_ALG)


def set_auth_cookies(response, user_id, remember=True):
    response.set_cookie("access_token", make_token(user_id, "access", 30), httponly=True, secure=True,
                        samesite="none", max_age=1800, path="/")
    response.set_cookie("refresh_token", make_token(user_id, "refresh", 60 * 24 * (7 if remember else 1)), httponly=True,
                        secure=True, samesite="none", max_age=604800 if remember else None, path="/")


async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    auth = request.headers.get("Authorization", "")
    if not token and auth.startswith("Bearer "):
        token = auth[7:]
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid session")
    if payload.get("type") != "access":
        raise HTTPException(401, "Invalid session")
    if await db.revoked_tokens.find_one({"jti": payload.get("jti")}):
        raise HTTPException(401, "Session revoked")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user or user.get("disabled"):
        raise HTTPException(401, "User not found")
    user["_jti"] = payload.get("jti")
    return user


async def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        await security_event("authorization_denied", "medium", f"Non-admin {user['email']} attempted admin action", user)
        raise HTTPException(403, "Admin role required")
    return user


def owner_filter(user):
    if user.get("role") == "admin":
        return {}
    return {"owner_id": user["id"]}


def dataset_filter(user):
    if user.get("role") == "admin":
        return {}
    return {"$or": [{"owner_id": user["id"]}, {"owner_id": "system"}]}


async def audit(action, user=None, target=None, detail=None):
    await db.audit_logs.insert_one({"id": new_id("aud"), "ts": now(), "action": action,
                                    "user_id": (user or {}).get("id"), "user_email": (user or {}).get("email"),
                                    "target": target, "detail": detail})


async def security_event(kind, severity, message, user=None, payload=None, review=False):
    await db.security_events.insert_one({"id": new_id("sec"), "ts": now(), "kind": kind, "severity": severity,
                                         "message": message, "user_email": (user or {}).get("email"),
                                         "payload": (payload or "")[:500],
                                         "status": "pending_review" if review else "logged"})


INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts)", "instruction_hijacking"),
    (r"(reveal|show|print|display|leak)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions)", "system_prompt_extraction"),
    (r"system\s+prompt", "system_prompt_extraction"),
    (r"\byou are now\b|\bdeveloper mode\b|\bjailbreak\b|\bDAN\b", "instruction_hijacking"),
    (r"(api[_\s-]?key|secret[_\s-]?key|jwt[_\s-]?secret|password[_\s]hash|credentials|os\.environ|\.env\b)", "secret_exfiltration"),
    (r"(__import__|\bimport\s+os\b|\bsubprocess\b|\beval\s*\(|\bexec\s*\(|rm\s+-rf|/etc/passwd)", "unsafe_code_request"),
    (r"(drop\s+table|;\s*delete\s+from|union\s+select|\$where|\$ne\b)", "injection_attempt"),
    (r"<\s*script|javascript:", "xss_attempt"),
    (r"(other|all)\s+users?'?\s*(data|datasets|files)|another\s+user'?s", "unauthorized_data_access"),
    (r"(send|post|upload|exfiltrate)\s+.*\s+(to|via)\s+(http|url|webhook|email)", "data_exfiltration"),
]


def detect_injection(text):
    hits = []
    for pat, kind in INJECTION_PATTERNS:
        if re.search(pat, text or "", re.IGNORECASE):
            hits.append(kind)
    return sorted(set(hits))


class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)

    def check(self, key, limit, window=60):
        q = self.hits[key]
        t = time.time()
        while q and q[0] < t - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(t)
        return True


limiter = RateLimiter()


def client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")

