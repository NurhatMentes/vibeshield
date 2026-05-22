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

// --- AES-256-GCM ENCRYPTION ---

function get32ByteKey(secret: string): Buffer {
  return crypto.createHash('sha256').update(secret).digest();
}

export function encryptAES(text: string, secret: string): string {
  if (typeof text !== 'string') text = JSON.stringify(text);
  
  const iv = crypto.randomBytes(12);
  const key = get32ByteKey(secret);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  
  return `gcm:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decryptAES(cipherText: string, secret: string): string {
  try {
    const parts = cipherText.split(':');
    if (parts.length !== 4 || parts[0] !== 'gcm') return cipherText; // Fallback if not our format
    
    const [, ivHex, authTagHex, encryptedHex] = parts;
    const key = get32ByteKey(secret);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    // If decryption fails (e.g. tampered data), return original or throw? 
    // In secure systems, tampering should fail hard, but for transparent proxies returning null/original is sometimes safer to avoid crashing. 
    // We will return a masked error string to prevent leakage.
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
        // We encrypt the value as a JSON string if it's not a string
        const strVal = typeof value === 'string' ? value : JSON.stringify(value);
        result[key] = encryptAES(strVal, secret);
      } else {
        if (typeof value === 'string' && value.startsWith('gcm:')) {
          const decrypted = decryptAES(value, secret);
          // Try to parse JSON back if it was an object/number
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
