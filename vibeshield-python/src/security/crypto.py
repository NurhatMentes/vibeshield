import os
import hmac
import hashlib
import json
import base64
from typing import Any, List, Dict, Union, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- HMAC SIGNATURES ---

def generate_hmac(data: str, secret: str) -> str:
    """Generate an HMAC-SHA256 signature for the given data."""
    return hmac.new(
        key=secret.encode('utf-8'),
        msg=data.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

def verify_hmac(data: str, signature: str, secret: str) -> bool:
    """Securely verify an HMAC-SHA256 signature to prevent timing attacks."""
    try:
        expected = generate_hmac(data, secret)
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False

# --- PASSWORD HASHING (PBKDF2) ---

def hash_password(password: str) -> str:
    """Generate a PBKDF2-SHA512 salted password hash."""
    salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac(
        hash_name='sha512',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=100000,
        dklen=64
    )
    return f"pbkdf2${salt.hex()}${hash_bytes.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a PBKDF2-SHA512 password hash."""
    try:
        parts = stored_hash.split('$')
        if len(parts) != 3 or parts[0] != 'pbkdf2':
            return False
        
        algo, salt_hex, hash_hex = parts
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        
        computed_hash = hashlib.pbkdf2_hmac(
            hash_name='sha512',
            password=password.encode('utf-8'),
            salt=salt,
            iterations=100000,
            dklen=64
        )
        return hmac.compare_digest(expected_hash, computed_hash)
    except Exception:
        return False

# --- AES-256-GCM ENCRYPTION WITH HKDF KEY DERIVATION ---

def _get_32_byte_key(secret: str) -> bytes:
    """Derive a 32-byte AES-256 key from a string secret using SHA256 (old method)."""
    return hashlib.sha256(secret.encode('utf-8')).digest()

def hkdf_sha256(ikm: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    """Standard HKDF-SHA256 implementation in pure Python."""
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b''
    t = b''
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

def derive_key(secret: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Derive a 32-byte AES-256 key from a string secret using HKDF-SHA256."""
    actual_salt = salt or os.urandom(16)
    try:
        key = hashlib.hkdf(
            ikm=secret.encode('utf-8'),
            salt=actual_salt,
            info=b'vibeshield-encryption-v1',
            length=32,
            algorithm='sha256'
        )
    except AttributeError:
        key = hkdf_sha256(
            ikm=secret.encode('utf-8'),
            length=32,
            salt=actual_salt,
            info=b'vibeshield-encryption-v1'
        )
    return key, actual_salt

def encrypt_aes(text: Union[str, dict, list], secret: str) -> str:
    """Encrypt a string or dict/list using AES-256-GCM and HKDF key derivation."""
    if not isinstance(text, str):
        text = json.dumps(text, separators=(',', ':'))
        
    key, salt = derive_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    # Encrypts the data and appends the 16-byte authentication tag
    cipher_data = aesgcm.encrypt(nonce, text.encode('utf-8'), associated_data=None)
    
    cipher_text = cipher_data[:-16]
    auth_tag = cipher_data[-16:]
    
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    cipher_b64 = base64.b64encode(cipher_text).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    auth_tag_b64 = base64.b64encode(auth_tag).decode('utf-8')
    
    return f"gcm:enc:{salt_b64}:{cipher_b64}:{nonce_b64}:{auth_tag_b64}"

def decrypt_aes(cipher_text: str, secret: str) -> str:
    """Decrypt an AES-256-GCM cipher string supporting multiple formats."""
    try:
        if not isinstance(cipher_text, str):
            return cipher_text
        if not cipher_text.startswith('gcm:'):
            return cipher_text
            
        parts = cipher_text.split(':')
        
        # Support new format: gcm:enc:base64(salt):base64(ciphertext):base64(iv):base64(tag) -> length 6
        if len(parts) == 6 and parts[0] == 'gcm' and parts[1] == 'enc':
            salt = base64.b64decode(parts[2])
            cipher_bytes = base64.b64decode(parts[3])
            nonce = base64.b64decode(parts[4])
            auth_tag = base64.b64decode(parts[5])
            
            key, _ = derive_key(secret, salt)
            aesgcm = AESGCM(key)
            cipher_data = cipher_bytes + auth_tag
            
            decrypted_bytes = aesgcm.decrypt(nonce, cipher_data, associated_data=None)
            return decrypted_bytes.decode('utf-8')
            
        # Support old base64 format: gcm:enc:base64(ciphertext):base64(iv):base64(tag) -> length 5
        if len(parts) == 5 and parts[0] == 'gcm' and parts[1] == 'enc':
            cipher_bytes = base64.b64decode(parts[2])
            nonce = base64.b64decode(parts[3])
            auth_tag = base64.b64decode(parts[4])
            
            key = _get_32_byte_key(secret)
            aesgcm = AESGCM(key)
            cipher_data = cipher_bytes + auth_tag
            
            decrypted_bytes = aesgcm.decrypt(nonce, cipher_data, associated_data=None)
            return decrypted_bytes.decode('utf-8')

        # Support old hex format: gcm:ivHex:authTagHex:encryptedHex -> length 4
        if len(parts) == 4 and parts[0] == 'gcm':
            _, nonce_hex, auth_tag_hex, enc_hex = parts
            key = _get_32_byte_key(secret)
            aesgcm = AESGCM(key)
            
            nonce = bytes.fromhex(nonce_hex)
            cipher_data = bytes.fromhex(enc_hex) + bytes.fromhex(auth_tag_hex)
            
            decrypted_bytes = aesgcm.decrypt(nonce, cipher_data, associated_data=None)
            return decrypted_bytes.decode('utf-8')
            
        return cipher_text
    except Exception:
        return "[[DECRYPTION_FAILED]]"

# --- RECURSIVE FIELD ENGINE ---

def process_crypto_fields(val: Any, fields: List[str], encrypt: bool, secret: str) -> Any:
    """
    Recursively traverse an object (dict, list) and encrypt/decrypt specific fields.
    """
    if val is None or not isinstance(val, (dict, list)):
        return val

    if isinstance(val, list):
        return [process_crypto_fields(item, fields, encrypt, secret) for item in val]

    result = {}
    for k, v in val.items():
        if k in fields:
            if encrypt:
                str_val = v if isinstance(v, str) else json.dumps(v, separators=(',', ':'))
                result[k] = encrypt_aes(str_val, secret)
            else:
                if isinstance(v, str) and v.startswith('gcm:'):
                    decrypted = decrypt_aes(v, secret)
                    try:
                        result[k] = json.loads(decrypted)
                    except json.JSONDecodeError:
                        result[k] = decrypted
                else:
                    result[k] = v
        elif isinstance(v, (dict, list)):
            result[k] = process_crypto_fields(v, fields, encrypt, secret)
        else:
            result[k] = v
            
    return result
