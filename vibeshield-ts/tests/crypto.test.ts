import { describe, it, expect } from 'vitest';
import {
  generateHMAC,
  verifyHMAC,
  hashPassword,
  verifyPassword,
  encryptAES,
  decryptAES,
  processCryptoFields,
} from '../src/core/security/crypto.js';

describe('VibeShield Crypto Engine (TypeScript)', () => {
  const secretKey = 'super_secret_key_for_testing_purposes';

  it('should sign and verify HMAC-SHA256 signatures', () => {
    const payload = JSON.stringify({ userId: 123, role: 'admin' });
    const signature = generateHMAC(payload, secretKey);
    
    expect(verifyHMAC(payload, signature, secretKey)).toBe(true);
    expect(verifyHMAC(payload, signature, 'wrong_key')).toBe(false);
    expect(verifyHMAC('{"userId":123,"role":"user"}', signature, secretKey)).toBe(false);
  });

  it('should hash and verify passwords using PBKDF2', () => {
    const password = 'my_secure_password';
    const hashStr = hashPassword(password);
    
    expect(hashStr).toContain('pbkdf2$');
    expect(verifyPassword(password, hashStr)).toBe(true);
    expect(verifyPassword('wrong_password', hashStr)).toBe(false);
  });

  it('should encrypt and decrypt strings using AES-256-GCM', () => {
    const plainText = 'sensitive_credit_card_data';
    const cipherText = encryptAES(plainText, secretKey);
    
    expect(cipherText).toContain('gcm:');
    expect(cipherText).not.toContain(plainText);
    
    const decrypted = decryptAES(cipherText, secretKey);
    expect(decrypted).toBe(plainText);
  });

  it('should recursively encrypt specified fields in an object', () => {
    const data = {
      id: 1,
      user: {
        name: 'Alice',
        ssn: '123-45-678',
      },
      metadata: [
        { key: 'creditCard', value: '1234' },
        { creditCard: '5555-4444-3333-2222' }
      ]
    };

    const encryptedData = processCryptoFields(data, ['ssn', 'creditCard'], true, secretKey);
    
    expect(encryptedData.id).toBe(1);
    expect(encryptedData.user.name).toBe('Alice');
    
    // SSN should be encrypted
    expect(encryptedData.user.ssn).toContain('gcm:');
    expect(encryptedData.user.ssn).not.toBe('123-45-678');
    
    // Nested array creditCard should be encrypted
    expect(encryptedData.metadata[1].creditCard).toContain('gcm:');
    expect(encryptedData.metadata[1].creditCard).not.toBe('5555-4444-3333-2222');
  });

  it('should recursively decrypt specified fields in an object', () => {
    const cipherText = encryptAES('123-45-678', secretKey);
    const data = {
      user: { ssn: cipherText },
      unrelated: 'plain'
    };

    const decryptedData = processCryptoFields(data, ['ssn'], false, secretKey);
    
    expect(decryptedData.user.ssn).toBe('123-45-678');
    expect(decryptedData.unrelated).toBe('plain');
  });

  it('should generate different keys/ciphertexts for different salts (HKDF)', () => {
    const plainText = 'sensitive_credit_card_data';
    const cipherText1 = encryptAES(plainText, secretKey);
    const cipherText2 = encryptAES(plainText, secretKey);
    
    expect(cipherText1).not.toBe(cipherText2);
    expect(decryptAES(cipherText1, secretKey)).toBe(plainText);
    expect(decryptAES(cipherText2, secretKey)).toBe(plainText);
  });

  it('should support backward compatibility with old hex format', () => {
    const oldCipherText = "gcm:c6c0606fc58701be32942917:9ff2c70aadfd38acb838e97fb07324ff:6319b2944d";
    const decrypted = decryptAES(oldCipherText, "secret");
    expect(decrypted).toBe("hello");
  });
});
