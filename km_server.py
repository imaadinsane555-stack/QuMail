"""
km_server.py — Simple Key Manager (FastAPI)
- identity register/fetch
- sessions (QKD-sim) request & fetch
- otp request & fetch
- stores data in JSON files under ~/.qumail_km (simple for demo)
"""

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List, Dict, Optional
import os, json, time, base64, secrets, threading

APP_DIR = os.path.join(os.path.expanduser("~"), ".qumail_km")
os.makedirs(APP_DIR, exist_ok=True)
IDENT_PATH = os.path.join(APP_DIR, "identities.json")
SESS_PATH = os.path.join(APP_DIR, "sessions.json")
OTP_PATH = os.path.join(APP_DIR, "otps.json")
LOCK = threading.Lock()

def _load(p, default):
    if not os.path.exists(p):
        return default
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save(p, data):
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(p + ".tmp", p)

# storage
def load_all():
    with LOCK:
        idents = _load(IDENT_PATH, {})
        sess = _load(SESS_PATH, {})
        otps = _load(OTP_PATH, {})
        return idents, sess, otps

def save_all(idents, sess, otps):
    with LOCK:
        _save(IDENT_PATH, idents)
        _save(SESS_PATH, sess)
        _save(OTP_PATH, otps)

app = FastAPI()

class RegisterModel(BaseModel):
    email: str
    pubkey: str
    alg: Optional[str] = "kyber"  # metadata

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/keys/register")
def register_key(payload: RegisterModel):
    idents, sess, otps = load_all()
    idents[payload.email.lower()] = {
        "pubkey": payload.pubkey,
        "alg": payload.alg,
        "created_at": int(time.time()),
    }
    save_all(idents, sess, otps)
    return {"status": "ok"}

@app.get("/api/keys/identity/{email}")
def get_identity(email: str, scheme: Optional[str] = Query(None)):
    idents, sess, otps = load_all()
    e = email.lower()
    if e not in idents:
        raise HTTPException(status_code=404, detail="recipient key not found")
    entry = idents[e].copy()
    # optionally support aes key if present
    return {"pubkey": entry.get("pubkey"), "alg": entry.get("alg")}

# sessions for QKD-sim (ephemeral AES keys)
class SessionRequest(BaseModel):
    sender: str
    recipients: List[str]
    ttl_seconds: Optional[int] = 300
    one_time: Optional[bool] = True

@app.post("/api/sessions/request")
def request_session(req: SessionRequest):
    idents, sess, otps = load_all()
    ses_id = f"ses-{int(time.time())}-{secrets.token_hex(6)}"
    aes_map = {}
    for r in req.recipients:
        # per-recipient AES key (base64)
        key = secrets.token_bytes(32)
        aes_map[r.lower()] = base64.b64encode(key).decode("ascii")
    sess[ses_id] = {
        "aes_map": aes_map,
        "recipients": [r.lower() for r in req.recipients],
        "created_at": int(time.time()),
        "ttl": req.ttl_seconds or 300,
        "one_time": bool(req.one_time),
        "consumed": {r.lower(): False for r in req.recipients}
    }
    save_all(idents, sess, otps)
    return {"session_id": ses_id, "aes_map": aes_map}

@app.get("/api/sessions/{session_id}")
def get_session_key(session_id: str, recipient: str):
    idents, sess, otps = load_all()
    s = sess.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    if recipient.lower() not in s["recipients"]:
        raise HTTPException(status_code=403, detail="not a recipient")
    # TTL check
    if int(time.time()) - s["created_at"] > s["ttl"]:
        raise HTTPException(status_code=410, detail="session expired")
    if s["one_time"] and s["consumed"].get(recipient.lower(), False):
        raise HTTPException(status_code=410, detail="session key consumed")
    key = s["aes_map"].get(recipient.lower())
    if s["one_time"]:
        s["consumed"][recipient.lower()] = True
        save_all(idents, sess, otps)
    return {"aes_key_b64": key}

# OTP endpoints
class OTPRequest(BaseModel):
    sender: str
    recipients: List[str]
    length_bytes: int

@app.post("/api/otp/request")
def request_otp(req: OTPRequest):
    if req.length_bytes > 20000:
        raise HTTPException(status_code=400, detail="OTP length too large for demo (limit 20KB)")
    idents, sess, otps = load_all()
    otp_id = f"otp-{int(time.time())}-{secrets.token_hex(6)}"
    map_ = {}
    for r in req.recipients:
        data = secrets.token_bytes(req.length_bytes)
        map_[r.lower()] = base64.b64encode(data).decode("ascii")
    otps[otp_id] = {
        "map": map_,
        "recipients": [r.lower() for r in req.recipients],
        "created_at": int(time.time()),
        "consumed": {r.lower(): False for r in req.recipients},
    }
    save_all(idents, sess, otps)
    return {"otp_id": otp_id, "for": list(map_.keys())}

@app.get("/api/otp/{otp_id}")
def get_otp(otp_id: str, recipient: str):
    idents, sess, otps = load_all()
    o = otps.get(otp_id)
    if not o:
        raise HTTPException(status_code=404, detail="otp not found")
    if recipient.lower() not in o["recipients"]:
        raise HTTPException(status_code=403, detail="not a recipient")
    if o["consumed"].get(recipient.lower(), False):
        raise HTTPException(status_code=410, detail="otp consumed")
    data_b64 = o["map"].get(recipient.lower())
    o["consumed"][recipient.lower()] = True
    save_all(idents, sess, otps)
    return {"otp_b64": data_b64}
