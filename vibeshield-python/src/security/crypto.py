import os
import hmac
import hashlib
import json
from typing import Any, List, Dict, Union
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

# --- AES-256-GCM ENCRYPTION ---

def _get_32_byte_key(secret: str) -> bytes:
    """Derive a 32-byte AES-256 key from a string secret."""
    return hashlib.sha256(secret.encode('utf-8')).digest()

def encrypt_aes(text: Union[str, dict, list], secret: str) -> str:
    """Encrypt a string or dict/list using AES-256-GCM."""
    if not isinstance(text, str):
        text = json.dumps(text, separators=(',', ':'))
        
    key = _get_32_byte_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    # Encrypts the data and appends the 16-byte authentication tag
    cipher_data = aesgcm.encrypt(nonce, text.encode('utf-8'), associated_data=None)
    
    cipher_text = cipher_data[:-16]
    auth_tag = cipher_data[-16:]
    
    return f"gcm:{nonce.hex()}:{auth_tag.hex()}:{cipher_text.hex()}"

def decrypt_aes(cipher_text: str, secret: str) -> str:
    """Decrypt an AES-256-GCM cipher string."""
    try:
        parts = cipher_text.split(':')
        if len(parts) != 4 or parts[0] != 'gcm':
            return cipher_text
        
        _, nonce_hex, auth_tag_hex, enc_hex = parts
        
        key = _get_32_byte_key(secret)
        aesgcm = AESGCM(key)
        
        nonce = bytes.fromhex(nonce_hex)
        # AESGCM expects the cipher data + auth tag concatenated
        cipher_data = bytes.fromhex(enc_hex) + bytes.fromhex(auth_tag_hex)
        
        decrypted_bytes = aesgcm.decrypt(nonce, cipher_data, associated_data=None)
        return decrypted_bytes.decode('utf-8')
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
