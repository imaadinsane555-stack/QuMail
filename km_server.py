"""
km_server.py — Key Manager (FastAPI + Postgres via SQLAlchemy)
- Register/fetch identities
- Sessions (QKD-sim)
- OTP one-time pads
- Uses DATABASE_URL (Postgres on Render) or falls back to SQLite
"""

from fastapi import FastAPI, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import create_engine, Column, String, Integer, Boolean, JSON
from sqlalchemy.orm import sessionmaker, declarative_base, Session
import os, time, base64, secrets

# -------------------------------------------------------------------
# Database setup
# -------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./km.db")

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
app = FastAPI()

class RegisterModel(BaseModel):
    email: str
    pubkey: str
    alg: Optional[str] = "kyber"

@app.get("/health")
def health():
    return {"status": "ok"}

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
    return {"pubkey": identity.pubkey, "alg": identity.alg}

# -------------------------------------------------------------------
# Sessions (QKD-sim)
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
    for r in req.recipients:
        key = secrets.token_bytes(32)
        aes_map[r.lower()] = base64.b64encode(key).decode("ascii")

    sess_entry = {
        "aes_map": aes_map,
        "recipients": [r.lower() for r in req.recipients],
        "created_at": int(time.time()),
        "ttl": req.ttl_seconds or 300,
        "one_time": bool(req.one_time),
        "consumed": {r.lower(): False for r in req.recipients}
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
    if recipient.lower() not in data["recipients"]:
        raise HTTPException(status_code=403, detail="not a recipient")

    # TTL check
    if int(time.time()) - data["created_at"] > data["ttl"]:
        raise HTTPException(status_code=410, detail="session expired")

    if data["one_time"] and data["consumed"].get(recipient.lower(), False):
        raise HTTPException(status_code=410, detail="session key consumed")

    key = data["aes_map"].get(recipient.lower())
    if data["one_time"]:
        data["consumed"][recipient.lower()] = True
        s.data = data
        db.commit()

    return {"aes_key_b64": key}

# -------------------------------------------------------------------
# OTP (One-time pads)
# -------------------------------------------------------------------
class OTPRequest(BaseModel):
    sender: str
    recipients: List[str]
    length_bytes: int

@app.post("/api/otp/request")
def request_otp(req: OTPRequest, db: Session = Depends(get_db)):
    if req.length_bytes > 20000:
        raise HTTPException(status_code=400, detail="OTP length too large (max 20KB)")

    otp_id = f"otp-{int(time.time())}-{secrets.token_hex(6)}"
    map_ = {}
    for r in req.recipients:
        data = secrets.token_bytes(req.length_bytes)
        map_[r.lower()] = base64.b64encode(data).decode("ascii")

    otp_entry = {
        "map": map_,
        "recipients": [r.lower() for r in req.recipients],
        "created_at": int(time.time()),
        "consumed": {r.lower(): False for r in req.recipients}
    }

    db.add(OTPModel(id=otp_id, data=otp_entry))
    db.commit()
    return {"otp_id": otp_id, "for": list(map_.keys())}

@app.get("/api/otp/{otp_id}")
def get_otp(otp_id: str, recipient: str, db: Session = Depends(get_db)):
    o = db.query(OTPModel).filter(OTPModel.id == otp_id).first()
    if not o:
        raise HTTPException(status_code=404, detail="otp not found")

    data = o.data
    if recipient.lower() not in data["recipients"]:
        raise HTTPException(status_code=403, detail="not a recipient")

    if data["consumed"].get(recipient.lower(), False):
        raise HTTPException(status_code=410, detail="otp consumed")

    data_b64 = data["map"].get(recipient.lower())
    data["consumed"][recipient.lower()] = True
    o.data = data
    db.commit()
    return {"otp_b64": data_b64}
