import pytest
from src.security.crypto import (
    generate_hmac,
    verify_hmac,
    hash_password,
    verify_password,
    encrypt_aes,
    decrypt_aes,
    process_crypto_fields
)

SECRET_KEY = "super_secret_key_for_testing_purposes"

def test_hmac_signatures():
    payload = '{"userId": 123, "role": "admin"}'
    signature = generate_hmac(payload, SECRET_KEY)
    
    assert verify_hmac(payload, signature, SECRET_KEY) is True
    assert verify_hmac(payload, signature, "wrong_key") is False
    assert verify_hmac('{"userId": 123, "role": "user"}', signature, SECRET_KEY) is False

def test_password_hashing():
    password = "my_secure_password"
    hashed = hash_password(password)
    
    assert hashed.startswith("pbkdf2$")
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

def test_aes_gcm_encryption():
    plain_text = "sensitive_credit_card_data"
    cipher_text = encrypt_aes(plain_text, SECRET_KEY)
    
    assert cipher_text.startswith("gcm:")
    assert plain_text not in cipher_text
    
    decrypted = decrypt_aes(cipher_text, SECRET_KEY)
    assert decrypted == plain_text

def test_recursive_field_encryption():
    data = {
        "id": 1,
        "user": {
            "name": "Alice",
            "ssn": "123-45-678"
        },
        "metadata": [
            {"key": "creditCard", "value": "1234"},
            {"creditCard": "5555-4444-3333-2222"}
        ]
    }
    
    encrypted_data = process_crypto_fields(data, ["ssn", "creditCard"], True, SECRET_KEY)
    
    assert encrypted_data["id"] == 1
    assert encrypted_data["user"]["name"] == "Alice"
    
    assert encrypted_data["user"]["ssn"].startswith("gcm:")
    assert encrypted_data["user"]["ssn"] != "123-45-678"
    
    assert encrypted_data["metadata"][1]["creditCard"].startswith("gcm:")
    assert encrypted_data["metadata"][1]["creditCard"] != "5555-4444-3333-2222"

def test_recursive_field_decryption():
    cipher_text = encrypt_aes("123-45-678", SECRET_KEY)
    data = {
        "user": {"ssn": cipher_text},
        "unrelated": "plain"
    }
    
    decrypted_data = process_crypto_fields(data, ["ssn"], False, SECRET_KEY)
    
    assert decrypted_data["user"]["ssn"] == "123-45-678"
    assert decrypted_data["unrelated"] == "plain"
