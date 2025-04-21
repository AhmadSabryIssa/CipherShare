"""
crypto_utils.py  – resilient password helpers  (unchanged from earlier)
"""
from __future__ import annotations
import secrets, hashlib, hmac
from typing import Tuple

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.backends import default_backend
except Exception:
    Argon2id = None

TIME_COST, MEMORY_COST, PARALLELISM, HASH_LEN = 4, 2 ** 16, 2, 32
PBKDF2_ROUNDS = 200_000

def _argon2_or_none(pw: bytes, salt: bytes):
    if Argon2id is None: return None
    try:
        return Argon2id(salt=salt, time_cost=TIME_COST, memory_cost=MEMORY_COST,
                        parallelism=PARALLELISM, hash_len=HASH_LEN,
                        backend=default_backend())
    except TypeError:
        pass
    for sig in [(MEMORY_COST, TIME_COST), (TIME_COST, MEMORY_COST)]:
        try:
            return Argon2id(*sig, PARALLELISM, HASH_LEN, salt, default_backend())
        except TypeError:
            continue
    return None

def hash_password(password: str, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pw = password.encode()
    kdf = _argon2_or_none(pw, salt)
    if kdf:
        return kdf.hash(pw), salt
    digest = hashlib.pbkdf2_hmac("sha256", pw, salt, PBKDF2_ROUNDS, dklen=HASH_LEN)
    return digest, salt

def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
    pw = password.encode()
    kdf = _argon2_or_none(pw, salt)
    if kdf:
        try:
            kdf.verify_hash(hashed, pw); return True
        except Exception:
            return False
    test = hashlib.pbkdf2_hmac("sha256", pw, salt, PBKDF2_ROUNDS, dklen=HASH_LEN)
    return hmac.compare_digest(test, hashed)

# PBKDF2 key derivation (AES helpers kept for later)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 100_000,
                      backend=default_backend()).derive(password.encode())
