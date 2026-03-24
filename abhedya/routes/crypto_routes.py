"""
routes/crypto_routes.py  —  Abhedya API
========================================
POST /api/encrypt      encrypt text or uploaded file
POST /api/decrypt      decrypt .enc blob or base64 payload
POST /api/analyse-pw   password strength (JSON body: {password})
GET  /api/generate-pw  generate secure password (?length=N)
GET  /api/status       health / version info
"""
from __future__ import annotations
import base64, sys, os, logging
from flask import Blueprint, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.crypto_engine import encrypt_bytes, decrypt_bytes, KDF_ITERATIONS
from utils.security_utils import analyse, generate_password

log = logging.getLogger(__name__)
api = Blueprint("api", __name__)

_MAX_TEXT = 10 * 1024 * 1024   # 10 MB text ceiling


# ── helpers ────────────────────────────────────────────────────────────────────
def _field(name: str) -> str | None:
    if request.form.get(name):
        return request.form[name]
    js = request.get_json(silent=True)
    return (js or {}).get(name)

def _err(msg: str, code: int = 400):
    return jsonify({"success": False, "error": msg}), code


# ── /api/status ────────────────────────────────────────────────────────────────
@api.get("/status")
def status():
    return jsonify({
        "status":     "operational",
        "cipher":     "AES-256-GCM",
        "kdf":        "PBKDF2-HMAC-SHA256",
        "iterations": KDF_ITERATIONS,
        "tag_bits":   128,
        "salt_bytes": 16,
        "iv_bytes":   12,
    })


# ── /api/encrypt ───────────────────────────────────────────────────────────────
@api.post("/encrypt")
def encrypt_endpoint():
    password = _field("password")
    if not password:
        return _err("Password is required.")

    # Prefer file upload; fall back to text
    if "file" in request.files and request.files["file"].filename:
        f         = request.files["file"]
        plaintext = f.read()
        filename  = (f.filename or "file") + ".enc"
        is_text   = False
    else:
        text = _field("text") or ""
        if not text.strip():
            return _err("Provide text or upload a file to encrypt.")
        if len(text) > _MAX_TEXT:
            return _err("Text too large. Use file upload for large content.")
        plaintext = text.encode("utf-8")
        filename  = "message.enc"
        is_text   = True

    result = encrypt_bytes(plaintext, password)
    if not result.success:
        return _err(result.error, 422)

    pw_report = analyse(password)
    return jsonify({
        "success":       True,
        "encrypted_b64": base64.b64encode(result.data).decode(),
        "filename":      filename,
        "original_size": result.original_size,
        "output_size":   result.output_size,
        "overhead":      result.output_size - result.original_size,
        "elapsed_ms":    result.elapsed_ms,
        "is_text":       is_text,
        "password_info": {
            "label":   pw_report.label,
            "entropy": pw_report.entropy,
            "score":   pw_report.score,
            "color":   pw_report.color,
            "crack":   pw_report.crack_time,
        },
    })


# ── /api/decrypt ───────────────────────────────────────────────────────────────
@api.post("/decrypt")
def decrypt_endpoint():
    password = _field("password")
    if not password:
        return _err("Password is required.")

    blob: bytes | None = None
    filename = "decrypted"

    if "file" in request.files and request.files["file"].filename:
        f        = request.files["file"]
        blob     = f.read()
        filename = f.filename.removesuffix(".enc") or "decrypted"
    else:
        b64 = _field("encrypted_b64")
        if b64:
            try:
                blob = base64.b64decode(b64)
            except Exception:
                return _err("Invalid base64 data.")

    if not blob:
        return _err("Provide a .enc file or encrypted_b64 data.")

    result = decrypt_bytes(blob, password)
    if not result.success:
        return _err(result.error, 422)

    # Return UTF-8 text when possible; otherwise base64 binary
    try:
        text    = result.data.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        text    = base64.b64encode(result.data).decode()
        is_text = False

    return jsonify({
        "success":        True,
        "decrypted_text": text,
        "is_text":        is_text,
        "decrypted_size": result.output_size,
        "elapsed_ms":     result.elapsed_ms,
        "integrity":      "verified",
        "filename":       filename,
    })


# ── /api/analyse-pw ────────────────────────────────────────────────────────────
@api.post("/analyse-pw")
def analyse_pw():
    pw = (_field("password") or "")
    if not pw:
        return _err("No password provided.")
    r = analyse(pw)
    return jsonify({
        "entropy":     r.entropy,
        "score":       r.score,
        "label":       r.label,
        "color":       r.color,
        "crack_time":  r.crack_time,
        "issues":      r.issues,
        "suggestions": r.suggestions,
    })


# ── /api/generate-pw ───────────────────────────────────────────────────────────
@api.get("/generate-pw")
def gen_pw():
    try:
        length = int(request.args.get("length", 20))
        length = max(12, min(length, 64))
    except (ValueError, TypeError):
        length = 20
    pw = generate_password(length)
    r  = analyse(pw)
    return jsonify({
        "password":   pw,
        "entropy":    r.entropy,
        "score":      r.score,
        "label":      r.label,
        "color":      r.color,
        "crack_time": r.crack_time,
    })
