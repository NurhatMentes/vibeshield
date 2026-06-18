import crypto from 'node:crypto';

// --- HMAC SIGNATURES ---

export function generateHMAC(data: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

export function verifyHMAC(data: string, signature: string, secret: string): boolean {
  try {
    const expected = generateHMAC(data, secret);
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signature, 'hex'));
  } catch (e) {
    return false;
  }
}

// --- PASSWORD HASHING (PBKDF2) ---

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2$${salt}$${hash}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  try {
    const [algo, salt, hash] = storedHash.split('$');
    if (algo !== 'pbkdf2') return false;
    const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'));
  } catch (e) {
    return false;
  }
}

// --- AES-256-GCM ENCRYPTION WITH HKDF KEY DERIVATION ---

export function deriveKey(secret: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
  const actualSalt = salt || crypto.randomBytes(16);
  const key = crypto.hkdfSync('sha256', secret, actualSalt, 'vibeshield-encryption-v1', 32);
  return { key: Buffer.from(key), salt: actualSalt };
}

export function encryptAES(text: string, secret: string): string {
  if (typeof text !== 'string') text = JSON.stringify(text);
  
  const iv = crypto.randomBytes(12);
  const { key, salt } = deriveKey(secret);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag().toString('base64');
  
  return `gcm:enc:${salt.toString('base64')}:${encrypted}:${iv.toString('base64')}:${authTag}`;
}

export function decryptAES(cipherText: string, secret: string): string {
  try {
    if (typeof cipherText !== 'string') return cipherText;
    if (!cipherText.startsWith('gcm:')) return cipherText;

    const parts = cipherText.split(':');
    
    // Support new format: gcm:enc:base64(salt):base64(ciphertext):base64(iv):base64(tag) -> length 6
    if (parts.length === 6 && parts[0] === 'gcm' && parts[1] === 'enc') {
      const salt = Buffer.from(parts[2], 'base64');
      const encrypted = Buffer.from(parts[3], 'base64');
      const iv = Buffer.from(parts[4], 'base64');
      const authTag = Buffer.from(parts[5], 'base64');
      
      const { key } = deriveKey(secret, salt);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted);
      decrypted += decipher.final();
      return decrypted.toString('utf8');
    }
    
    // Support old base64 format: gcm:enc:base64(ciphertext):base64(iv):base64(tag) -> length 5
    if (parts.length === 5 && parts[0] === 'gcm' && parts[1] === 'enc') {
      const encrypted = Buffer.from(parts[2], 'base64');
      const iv = Buffer.from(parts[3], 'base64');
      const authTag = Buffer.from(parts[4], 'base64');
      
      // Derive key using old sha256 method
      const key = crypto.createHash('sha256').update(secret).digest();
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted);
      decrypted += decipher.final();
      return decrypted.toString('utf8');
    }

    // Support old hex format: gcm:ivHex:authTagHex:encryptedHex -> length 4
    if (parts.length === 4 && parts[0] === 'gcm') {
      const [, ivHex, authTagHex, encryptedHex] = parts;
      const key = crypto.createHash('sha256').update(secret).digest();
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
      decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
      
      let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }
    
    return cipherText;
  } catch (e) {
    return "[[DECRYPTION_FAILED]]";
  }
}

// --- RECURSIVE FIELD ENGINE ---

export function processCryptoFields(
  val: any,
  fields: string[],
  encrypt: boolean,
  secret: string
): any {
  if (!val || typeof val !== 'object') return val;

  if (Array.isArray(val)) {
    return val.map((item) => processCryptoFields(item, fields, encrypt, secret));
  }

  const result: any = {};
  for (const [key, value] of Object.entries(val)) {
    if (fields.includes(key)) {
      if (encrypt) {
        const strVal = typeof value === 'string' ? value : JSON.stringify(value);
        result[key] = encryptAES(strVal, secret);
      } else {
        if (typeof value === 'string' && value.startsWith('gcm:')) {
          const decrypted = decryptAES(value, secret);
          try {
            result[key] = JSON.parse(decrypted);
          } catch {
            result[key] = decrypted;
          }
        } else {
          result[key] = value;
        }
      }
    } else if (typeof value === 'object') {
      result[key] = processCryptoFields(value, fields, encrypt, secret);
    } else {
      result[key] = value;
    }
  }
  return result;
}
