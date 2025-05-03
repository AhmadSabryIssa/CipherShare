import os
import json
from pathlib import Path
from hashlib import sha256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

KEY_FILE = Path("GLOBAL_KEY.bin")
ACCESS_FILE = Path("access_requests.json")

def _load_or_create_key():
    if not KEY_FILE.exists():
        key = AESGCM.generate_key(bit_length=128)
        KEY_FILE.write_bytes(key)
    return KEY_FILE.read_bytes()

SYMMETRIC_KEY = _load_or_create_key()

def encrypt_file(data: bytes):
    aesgcm = AESGCM(SYMMETRIC_KEY)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return nonce, encrypted

def decrypt_file(nonce: bytes, ciphertext: bytes):
    aesgcm = AESGCM(SYMMETRIC_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)

def hash_password(password: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def verify_password(password: str, key: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), key)
        return True
    except Exception:
        return False

def load_access_requests():
    if ACCESS_FILE.exists():
        return json.loads(ACCESS_FILE.read_text())
    return {"request": {}, "grant": {}}

def save_access_requests(data):
    ACCESS_FILE.write_text(json.dumps(data, indent=2))
