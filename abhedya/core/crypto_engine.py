"""
core/crypto_engine.py  —  AES-256-GCM authenticated encryption engine
======================================================================
Security spec:
  Cipher      : AES-256-GCM  (AEAD — confidentiality + integrity)
  KDF         : PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023)
  Salt        : 16 bytes, os.urandom(), fresh per operation
  IV / Nonce  : 12 bytes, os.urandom(), fresh per operation
  Auth Tag    : 16 bytes (128-bit GCM tag)
  Key size    : 32 bytes (AES-256)
  Fail-closed : plaintext never exposed when tag verification fails

Wire format  (45-byte header + N-byte ciphertext):
  [1B ver][16B salt][12B IV][16B tag][…ciphertext…]
"""

from __future__ import annotations
import os, struct, time, logging
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

FILE_VERSION   = 0x01
SALT_LEN       = 16
IV_LEN         = 12
TAG_LEN        = 16
KEY_LEN        = 32
KDF_ITERATIONS = 600_000          # OWASP 2023 minimum for PBKDF2-SHA256
HEADER_LEN     = 1 + SALT_LEN + IV_LEN + TAG_LEN   # 45 bytes
MAX_SIZE       = 100 * 1024 * 1024  # 100 MB


@dataclass
class EncryptResult:
    success: bool
    data: bytes = b""
    elapsed_ms: float = 0.0
    original_size: int = 0
    output_size: int = 0
    error: str = ""


@dataclass
class DecryptResult:
    success: bool
    data: bytes = b""
    elapsed_ms: float = 0.0
    output_size: int = 0
    error: str = ""


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> EncryptResult:
    if not password or len(password) < 8:
        return EncryptResult(success=False, error="Password must be at least 8 characters.")
    if len(plaintext) > MAX_SIZE:
        return EncryptResult(success=False, error="File too large. Maximum: 100 MB.")

    t = time.perf_counter()
    try:
        salt   = os.urandom(SALT_LEN)
        iv     = os.urandom(IV_LEN)
        key    = _derive_key(password, salt)
        ct_tag = AESGCM(key).encrypt(iv, plaintext, None)
        blob   = struct.pack("B", FILE_VERSION) + salt + iv + ct_tag[-TAG_LEN:] + ct_tag[:-TAG_LEN]
        ms     = round((time.perf_counter() - t) * 1000, 1)
        logger.info("Encrypted %d → %d bytes in %.1f ms", len(plaintext), len(blob), ms)
        return EncryptResult(success=True, data=blob, elapsed_ms=ms,
                             original_size=len(plaintext), output_size=len(blob))
    except Exception as e:
        logger.error("encrypt_bytes: %s", e)
        return EncryptResult(success=False, error="Encryption failed. Please try again.")


def decrypt_bytes(blob: bytes, password: str) -> DecryptResult:
    if not password:
        return DecryptResult(success=False, error="Password is required.")
    if len(blob) < HEADER_LEN + 1:
        return DecryptResult(success=False, error="Invalid or corrupted file.")

    t = time.perf_counter()
    try:
        ver = struct.unpack("B", blob[:1])[0]
        if ver != FILE_VERSION:
            return DecryptResult(success=False, error="Unrecognised file format.")

        off      = 1
        salt     = blob[off:off+SALT_LEN];  off += SALT_LEN
        iv       = blob[off:off+IV_LEN];    off += IV_LEN
        tag      = blob[off:off+TAG_LEN];   off += TAG_LEN
        ct       = blob[off:]
        key      = _derive_key(password, salt)
        plain    = AESGCM(key).decrypt(iv, ct + tag, None)
        ms       = round((time.perf_counter() - t) * 1000, 1)
        logger.info("Decrypted %d bytes in %.1f ms", len(plain), ms)
        return DecryptResult(success=True, data=plain, elapsed_ms=ms, output_size=len(plain))

    except InvalidTag:
        return DecryptResult(success=False,
            error="Incorrect password, or file has been modified / corrupted.")
    except Exception as e:
        logger.error("decrypt_bytes: %s", e)
        return DecryptResult(success=False, error="Decryption failed. File may be corrupted.")
