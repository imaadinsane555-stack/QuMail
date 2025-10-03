"""
qumail_crypto.py — client-side crypto API for QuMail
Supports 4 security levels:
1 = OTP (requests OTP from KM)
2 = QKD-sim AES sessions (requests session from KM)
3 = PQC-sim (KEM-style encapsulation + AES)
4 = AES fallback (fetch shared AES from KM identity if present)

This file intentionally simulates PQC/KEM to avoid heavy native deps.
Uses 'cryptography' for AES-GCM.
"""

import os, json, base64, requests, secrets
from typing import List, Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# helper
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")
def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# -------- keypair (PQC-sim) ----------
def generate_kem_keypair() -> Tuple[str,str]:
    """
    Simulate a KEM keypair by generating two random blobs as pub/priv (base64).
    In real product, replace with actual Kyber / pyoqs outputs.
    """
    pub = secrets.token_bytes(64)
    priv = secrets.token_bytes(64)
    return b64(pub), b64(priv)

# -------- KM interactions ----------
class KMError(Exception): pass
class CryptoError(Exception): pass

def register_identity(km_base_url: str, email: str, pub_b64: str):
    url = km_base_url.rstrip("/") + "/api/keys/register"
    r = requests.post(url, json={"email": email, "pubkey": pub_b64})
    if r.status_code != 200:
        raise KMError(r.text)
    return r.json()

def fetch_pubkey(km_base_url: str, email: str) -> str:
    url = km_base_url.rstrip("/") + f"/api/keys/identity/{email}"
    r = requests.get(url)
    if r.status_code == 404:
        raise KMError("recipient key not found")
    if r.status_code != 200:
        raise KMError(r.text)
    j = r.json()
    return j.get("pubkey")

# --------- AES helper ----------
def aes_encrypt(key: bytes, plaintext: bytes, associated=b"") -> Dict[str,str]:
    aesg = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesg.encrypt(nonce, plaintext, associated)
    return {"ciphertext": b64(ct), "nonce": b64(nonce)}

def aes_decrypt(key: bytes, ciphertext_b64: str, nonce_b64: str, associated=b"") -> bytes:
    aesg = AESGCM(key)
    ct = ub64(ciphertext_b64)
    nonce = ub64(nonce_b64)
    return aesg.decrypt(nonce, ct, associated)

# --------- Encryption API ----------
def encrypt_message(sender: str, from_priv_b64: str, recipients: List[str], plaintext: bytes, attachments: List[Dict[str, bytes]], km_base_url: str, security_level: int = 2) -> Dict[str, Any]:
    """
    Returns envelope dict (JSON-serializable). Attachments is list of {"name", "data"} where data is bytes.
    security_level: 1..4
    """
    if security_level == 1:
        # OTP: request OTP from KM sized to plaintext+attachments
        total_len = len(plaintext)
        for a in attachments or []:
            total_len += len(a.get("data", b""))
        url = km_base_url.rstrip("/") + "/api/otp/request"
        r = requests.post(url, json={"sender": sender, "recipients": recipients, "length_bytes": total_len})
        if r.status_code != 200:
            raise KMError(f"OTP request failed: {r.text}")
        j = r.json()
        otp_id = j["otp_id"]
        # take OTP bytes for sender side (we expect KM returned map on creation)
        # But in our KM, the POST returned only id & recipients; we didn't include bytes back
        # To keep it simple, we'll fetch the otp for sender (KM returns bytes)
        rr = requests.get(km_base_url.rstrip("/") + f"/api/otp/{otp_id}", params={"recipient": sender})
        if rr.status_code != 200:
            raise KMError("Failed to fetch OTP for sender")
        otp_b64 = rr.json()["otp_b64"]
        otp = ub64(otp_b64)
        # XOR plaintext+attachments into ciphertext blob layout: we concatenate message + attachments bytes and send as one ciphertext
        payload = plaintext
        for a in attachments or []:
            payload += b"\n--ATTACHMENT--\n" + a.get("name", "").encode("utf-8") + b"\n" + a.get("data", b"")
        if len(otp) < len(payload):
            raise CryptoError("OTP too short")
        ct = bytes([payload[i] ^ otp[i] for i in range(len(payload))])
        env = {"security_level":1, "scheme":"otp", "otp_id": otp_id, "ciphertext": b64(ct)}
        return env

    if security_level == 2:
        # QKD-sim: request session AES key from KM
        url = km_base_url.rstrip("/") + "/api/sessions/request"
        r = requests.post(url, json={"sender": sender, "recipients": recipients, "ttl_seconds": 300, "one_time": True})
        if r.status_code != 200:
            raise KMError(f"session request failed: {r.text}")
        j = r.json()
        session_id = j["session_id"]
        # for sending, we need the AES key for sender's encrypt step — KM returned per-recipient keys in creation response (aes_map)
        aes_map = j.get("aes_map", {})
        # for simplicity use the sender's aes key if present for encryption
        key_b64 = aes_map.get(sender) or list(aes_map.values())[0]
        aes_key = ub64(key_b64)
        # encrypt
        payload = plaintext
        for a in attachments or []:
            payload += b"\n--ATTACHMENT--\n" + a.get("name","").encode("utf-8") + b"\n" + a.get("data", b"")
        enc = aes_encrypt(aes_key, payload)
        env = {"security_level":2, "scheme":"qkd-sim-aes", "session_id": session_id, "ciphertext": enc["ciphertext"], "nonce": enc["nonce"]}
        return env

    if security_level == 3:
        # PQC-sim KEM: for each recipient, perform a simulated encapsulation
        recipients_block = {}
        # generate a fresh AES key to encrypt payload, then for each recipient provide an "encapsulation blob"
        aes_key = secrets.token_bytes(32)
        for r in recipients:
            # fetch pubkey (we only need to ensure recipient exists)
            pub = fetch_pubkey(km_base_url, r)
            # create a fake encapsulation blob: base64(random + pub fingerprint)
            blob = b64(secrets.token_bytes(64))
            recipients_block[r] = {"enc": blob, "alg": "kyber-sim"}
        payload = plaintext
        for a in attachments or []:
            payload += b"\n--ATTACHMENT--\n" + a.get("name","").encode("utf-8") + b"\n" + a.get("data", b"")
        enc = aes_encrypt(aes_key, payload)
        env = {"security_level":3, "scheme":"pqc-kyber+aes-gcm", "recipients": recipients_block, "ciphertext": enc["ciphertext"], "nonce": enc["nonce"], "meta": {"sender": sender}}
        # store aes_key in envelope encoded (in real KEM, not stored — each recipient decapsulates; here we simulate by storing an encrypted copy per recipient would be required, but for demo we will require client to use 'fake' decapsulation: the recipient will call decrypt_message_for_recipient which will produce same aes_key if we encode it into enc blob in a reversible way)
        # For simplicity, include a symmetric wrap: put aes_key B64 inside each recipient.enc but XORed with pub fingerprint — but to keep code simpler, we will embed aes_key in env['__sim_aes_b64'] (private to demo clients). Real product MUST NOT do this.
        env["__sim_aes_b64"] = b64(aes_key)
        return env

    if security_level == 4:
        # AES fallback: fetch a stored aes key from KM identity endpoint (not implemented in km_server for aes; but KM may store pub-key area)
        # We'll attempt to fetch identity and look for 'aes_key' if present; else raise
        url = km_base_url.rstrip("/") + f"/api/keys/identity/{recipients[0]}"
        r = requests.get(url)
        if r.status_code != 200:
            raise KMError("failed to fetch identity for aes fallback")
        j = r.json()
        # check for 'aes_key' field in j (KM would have to store it)
        aes_key_b64 = j.get("aes_key")
        if not aes_key_b64:
            raise KMError("aes key not provisioned for recipient")
        aes_key = ub64(aes_key_b64)
        payload = plaintext
        for a in attachments or []:
            payload += b"\n--ATTACHMENT--\n" + a.get("name","").encode("utf-8") + b"\n" + a.get("data", b"")
        enc = aes_encrypt(aes_key, payload)
        env = {"security_level":4, "scheme":"aes-fallback", "ciphertext": enc["ciphertext"], "nonce": enc["nonce"], "recipients": {recipients[0]: {"key_id": f"{recipients[0]}:aes:v1"}}}
        return env

    raise CryptoError("unknown security level")

# ---------- Decrypt ----------
def decrypt_message_for_recipient(envelope: Dict[str, Any], recipient_email: str, priv_b64: str, km_base_url: str) -> Tuple[bytes, List[Dict[str, bytes]]]:
    level = int(envelope.get("security_level", 3))
    if level == 1:
        otp_id = envelope.get("otp_id")
        if not otp_id:
            raise CryptoError("otp_id missing")
        r = requests.get(km_base_url.rstrip("/") + f"/api/otp/{otp_id}", params={"recipient": recipient_email})
        if r.status_code != 200:
            raise KMError("failed to fetch OTP")
        otp_b64 = r.json()["otp_b64"]
        otp = ub64(otp_b64)
        ct = ub64(envelope.get("ciphertext"))
        if len(otp) < len(ct):
            raise CryptoError("OTP too short")
        payload = bytes([ct[i] ^ otp[i] for i in range(len(ct))])
        # naive unpack attachments split by marker
        if b"\n--ATTACHMENT--\n" in payload:
            # split first part into message and attachments
            parts = payload.split(b"\n--ATTACHMENT--\n")
            body = parts[0]
            atts = []
            i = 1
            while i + 1 < len(parts):
                name = parts[i].split(b"\n",1)[0].decode("utf-8")
                data = parts[i+1]
                atts.append({"name": name, "data": data})
                i += 2
            return body, atts
        return payload, []

    if level == 2:
        session_id = envelope.get("session_id")
        if not session_id:
            raise CryptoError("missing session id")
        r = requests.get(km_base_url.rstrip("/") + f"/api/sessions/{session_id}", params={"recipient": recipient_email})
        if r.status_code != 200:
            raise KMError("failed to fetch session key: " + r.text)
        key_b64 = r.json()["aes_key_b64"]
        key = ub64(key_b64)
        plaintext = aes_decrypt(key, envelope["ciphertext"], envelope["nonce"])
        # same naive attachment unpack
        if b"\n--ATTACHMENT--\n" in plaintext:
            parts = plaintext.split(b"\n--ATTACHMENT--\n")
            body = parts[0]
            atts = []
            i = 1
            while i + 1 < len(parts):
                name = parts[i].split(b"\n",1)[0].decode("utf-8")
                data = parts[i+1]
                atts.append({"name": name, "data": data})
                i += 2
            return body, atts
        return plaintext, []

    if level == 3:
        # PQC-sim: extract sim aes key present in envelope '__sim_aes_b64'
        sim = envelope.get("__sim_aes_b64")
        if not sim:
            raise CryptoError("missing sim aes key (demo)")
        aes_key = ub64(sim)
        plaintext = aes_decrypt(aes_key, envelope["ciphertext"], envelope["nonce"])
        # attachments
        if b"\n--ATTACHMENT--\n" in plaintext:
            parts = plaintext.split(b"\n--ATTACHMENT--\n")
            body = parts[0]
            atts = []
            i = 1
            while i + 1 < len(parts):
                name = parts[i].split(b"\n",1)[0].decode("utf-8")
                data = parts[i+1]
                atts.append({"name": name, "data": data})
                i += 2
            return body, atts
        return plaintext, []

    if level == 4:
        # AES fallback: fetch aes_key from identity (KM must provision aes_key)
        recs = envelope.get("recipients", {})
        keyid = list(recs.values())[0].get("key_id")
        # for demo, get identity info
        r = requests.get(km_base_url.rstrip("/") + f"/api/keys/identity/{recipient_email}")
        if r.status_code != 200:
            raise KMError("failed to fetch identity for aes fallback")
        j = r.json()
        aes_key_b64 = j.get("aes_key")
        if not aes_key_b64:
            raise KMError("aes key missing")
        key = ub64(aes_key_b64)
        plaintext = aes_decrypt(key, envelope["ciphertext"], envelope["nonce"])
        return plaintext, []
    raise CryptoError("unknown level")
