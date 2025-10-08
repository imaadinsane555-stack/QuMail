"""
QuMail KM Server (FastAPI + SQLAlchemy + Postgres)
-------------------------------------------------
Supports:
• Level 1 = OTP (one-time pads)
• Level 2 = QKD-sim (AES sessions)
• Level 3 = PQC-sim (Kyber-style pubkeys)
• Level 4 = AES fallback (identity-stored keys)

Includes admin token protection + full JSON backup.
"""

from fastapi import FastAPI, HTTPException, Query, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import create_engine, Column, String, Integer, Boolean, JSON
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import os, time, base64, secrets

# -------------------------------------------------------------------
# Database setup
# -------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./km.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------
class Identity(Base):
    __tablename__ = "identities"
    email = Column(String, primary_key=True, index=True)
    pubkey = Column(String)
    alg = Column(String, default="kyber")
    aes_key = Column(String, nullable=True)  # optional static AES fallback
    created_at = Column(Integer, default=lambda: int(time.time()))

class SessionModel(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, index=True)
    data = Column(JSON)

class OTPModel(Base):
    __tablename__ = "otps"
    id = Column(String, primary_key=True, index=True)
    data = Column(JSON)

Base.metadata.create_all(bind=engine)

# -------------------------------------------------------------------
# FastAPI app
# -------------------------------------------------------------------
app = FastAPI(title="QuMail KM Server")

@app.get("/health")
def health():
    return {"status": "ok"}

# -------------------------------------------------------------------
# Identity endpoints (Level 3 + Level 4)
# -------------------------------------------------------------------
class RegisterModel(BaseModel):
    email: str
    pubkey: str
    alg: Optional[str] = "kyber"

@app.post("/api/keys/register")
def register_key(payload: RegisterModel, db: Session = Depends(get_db)):
    identity = Identity(
        email=payload.email.lower(),
        pubkey=payload.pubkey,
        alg=payload.alg,
        created_at=int(time.time())
    )
    db.merge(identity)  # upsert
    db.commit()
    return {"status": "ok"}

@app.get("/api/keys/identity/{email}")
def get_identity(email: str, db: Session = Depends(get_db)):
    identity = db.query(Identity).filter(Identity.email == email.lower()).first()
    if not identity:
        raise HTTPException(status_code=404, detail="recipient key not found")
    out = {"pubkey": identity.pubkey, "alg": identity.alg}
    if identity.aes_key:
        out["aes_key"] = identity.aes_key
    return out

# -------------------------------------------------------------------
# Sessions (Level 2 QKD-AES)
# -------------------------------------------------------------------
class SessionRequest(BaseModel):
    sender: str
    recipients: List[str]
    ttl_seconds: Optional[int] = 300
    one_time: Optional[bool] = True

@app.post("/api/sessions/request")
def request_session(req: SessionRequest, db: Session = Depends(get_db)):
    ses_id = f"ses-{int(time.time())}-{secrets.token_hex(6)}"
    aes_map = {}
    # include sender + recipients
    for r in req.recipients + [req.sender]:
        key = secrets.token_bytes(32)
        aes_map[r.lower()] = base64.b64encode(key).decode("ascii")

    sess_entry = {
        "aes_map": aes_map,
        "recipients": [r.lower() for r in req.recipients],
        "sender": req.sender.lower(),
        "created_at": int(time.time()),
        "ttl": req.ttl_seconds or 300,
        "one_time": bool(req.one_time),
        "consumed": {r.lower(): False for r in req.recipients + [req.sender]},
    }

    db.add(SessionModel(id=ses_id, data=sess_entry))
    db.commit()
    return {"session_id": ses_id, "aes_map": aes_map}

@app.get("/api/sessions/{session_id}")
def get_session_key(session_id: str, recipient: str, db: Session = Depends(get_db)):
    s = db.query(SessionModel).filter(SessionModel.id == session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="session not found")

    data = s.data
    rec = recipient.lower()
    if rec not in data["aes_map"]:
        raise HTTPException(status_code=403, detail="not a participant")

    if int(time.time()) - data["created_at"] > data["ttl"]:
        raise HTTPException(status_code=410, detail="session expired")

    if data["one_time"] and data["consumed"].get(rec, False):
        raise HTTPException(status_code=410, detail="session key consumed")

    key = data["aes_map"][rec]
    if data["one_time"]:
        data["consumed"][rec] = True
        s.data = data
        db.commit()

    return {"aes_key_b64": key}

# -------------------------------------------------------------------
# OTP (Level 1)
# -------------------------------------------------------------------
class OTPRequest(BaseModel):
    sender: str
    recipients: List[str]
    length_bytes: int

@app.post("/api/otp/request")
def request_otp(req: OTPRequest, db: Session = Depends(get_db)):
    if req.length_bytes > 20000:
        raise HTTPException(status_code=400, detail="OTP length too large (max 20 KB)")
    otp_id = f"otp-{int(time.time())}-{secrets.token_hex(6)}"
    otp_map = {}
    for r in req.recipients + [req.sender]:
        data = secrets.token_bytes(req.length_bytes)
        otp_map[r.lower()] = base64.b64encode(data).decode("ascii")

    otp_entry = {
        "map": otp_map,
        "recipients": [r.lower() for r in req.recipients],
        "created_at": int(time.time()),
        "consumed": {r.lower(): False for r in req.recipients + [req.sender]},
    }

    db.add(OTPModel(id=otp_id, data=otp_entry))
    db.commit()
    return {"otp_id": otp_id, "for": list(otp_map.keys())}

@app.get("/api/otp/{otp_id}")
def get_otp(otp_id: str, recipient: str, db: Session = Depends(get_db)):
    o = db.query(OTPModel).filter(OTPModel.id == otp_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="otp not found")

    data = o.data
    rec = recipient.lower()
    if rec not in data["map"]:
        raise HTTPException(status_code=403, detail="not a participant")

    if data["consumed"].get(rec, False):
        raise HTTPException(status_code=410, detail="otp consumed")

    data_b64 = data["map"][rec]
    data["consumed"][rec] = True
    o.data = data
    db.commit()
    return {"otp_b64": data_b64}

# -------------------------------------------------------------------
# Admin (token-protected)
# -------------------------------------------------------------------
def verify_admin_token(header: Optional[str]) -> bool:
    if not ADMIN_TOKEN:
        print("[KM] WARNING: ADMIN_TOKEN not set – admin endpoints unprotected (dev only).")
        return True
    if not header or not header.startswith("Bearer "):
        return False
    return header.split("Bearer ",1)[1].strip() == ADMIN_TOKEN

@app.get("/api/admin/list_identities")
def admin_list(limit: int = Query(100, le=1000), authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not verify_admin_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    rows = db.query(Identity).order_by(Identity.created_at.desc()).limit(limit).all()
    return [{"email": r.email, "created_at": r.created_at} for r in rows]

@app.get("/api/admin/backup_all")
def admin_backup_all(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not verify_admin_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    ids = db.query(Identity).all()
    sess = db.query(SessionModel).all()
    otps = db.query(OTPModel).all()
    data = {
        "timestamp": int(time.time()),
        "identities": [{"email": i.email, "pubkey": i.pubkey, "alg": i.alg, "aes_key": i.aes_key, "created_at": i.created_at} for i in ids],
        "sessions": [{"id": s.id, "data": s.data} for s in sess],
        "otps": [{"id": o.id, "data": o.data} for o in otps],
    }
    data["counts"] = {k: len(v) for k, v in data.items() if isinstance(v, list)}
    return JSONResponse(data)

@app.delete("/api/admin/clear_all")
def admin_clear_all(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not verify_admin_token(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    db.query(Identity).delete()
    db.query(SessionModel).delete()
    db.query(OTPModel).delete()
    db.commit()
    return {"status": "cleared"}
