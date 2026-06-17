export interface PasswordContext {
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  birthDate?: string;
}

export interface PasswordValidationResult {
  valid: boolean;
  score: number;
  entropy: number;
  errors: string[];
  warnings: string[];
  strength: 'very_weak' | 'weak' | 'medium' | 'strong' | 'very_strong';
}

export interface PasswordPolicyOptions {
  minLength?: number;
  requireComplexity?: boolean;
}

export const COMMON_PASSWORDS = new Set([
  "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "letmein", "admin",
  "welcome", "monkey", "master", "dragon", "login", "princess", "football", "shadow", "sunshine", "trustno1",
  "1234567890", "1234", "111111", "123123", "password123", "admin123", "admin1234", "qwertyuiop",
  "hello", "computer", "keyboard", "master123", "guest", "root", "oracle", "secret", "security", "charlie",
  "alexander", "superman", "batman", "spiderman", "pokemon", "starwars", "soccer", "baseball", "basketball",
  "hockey", "chelsea", "arsenal", "liverpool", "manchester", "barcelona", "realmadrid", "juventus", "milan",
  "inter", "bayern", "dortmund", "schalke", "ajax", "psg", "marseille", "lyon", "monaco", "roma",
  "napoli", "lazio", "fiorentina", "torino", "sampdoria", "genoa", "bologna", "cagliari", "parma", "verona",
  "udinese", "lecce", "brescia", "spal", "sassuolo", "atalanta", "empoli", "frosinone", "chievo", "palermo",
  "catania", "bari", "siena", "livorno", "reggina", "messina", "ascoli", "treviso", "triestina", "vicenza",
  "perugia", "venezia", "ancona", "salernitana", "foggia", "avellino", "taranto", "brindisi", "potenza", "mater",
  "benvenuto", "amigo", "hola", "bonjour", "gutentag", "ciao", "privet", "nihao", "konnichiwa", "aloha",
  "sayonara", "adios", "aurevoir", "aufwiedersehen", "arrivederci", "poka", "zajian", "namaste", "shalom",
  "123456a", "123456b", "123456c", "123456d", "123456e", "123456f", "123456g", "123456h", "123456i", "123456j",
  "123456k", "123456l", "123456m", "123456n", "123456o", "123456p", "123456q", "123456r", "123456s", "123456t",
  "123456u", "123456v", "123456w", "123456x", "123456y", "123456z", "qwerty123", "qwerty12345", "qwertyuiop123",
  "password12", "password1234", "password12345", "password123456", "password1234567", "password12345678",
  "password123456789", "password1234567890", "letmeout", "letmein123", "letmein1234", "letmein12345", "letmein123456",
  "welcome1", "welcome12", "welcome123", "welcome1234", "welcome12345", "welcome123456", "monkey123", "monkey1234",
  "dragon123", "dragon1234", "master1234", "login123", "login1234", "guest123", "guest1234", "root123",
  "root1234", "secret123", "secret1234", "security123", "security1234", "spiderman1", "superman1", "batman1"
]);

export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function validatePassword(
  password: string,
  context?: PasswordContext,
  options?: PasswordPolicyOptions
): PasswordValidationResult {
  const minLength = options?.minLength ?? 12;
  const requireComplexity = options?.requireComplexity ?? true;
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!password) {
    return {
      valid: false,
      score: 0,
      entropy: 0,
      errors: ['Password cannot be empty'],
      warnings: [],
      strength: 'very_weak'
    };
  }

  // 1. Length checks
  if (password.length > 128) {
    errors.push('Password length exceeds maximum limit of 128 characters');
  }
  if (password.length < minLength) {
    errors.push(`Password is too short (minimum ${minLength} characters required)`);
  }

  const passwordLower = password.toLowerCase();

  // 2. Blacklist / Common Password Check
  const isCommon = COMMON_PASSWORDS.has(passwordLower);
  if (isCommon) {
    errors.push('Password is one of the most commonly used passwords');
  }

  // 3. Complexity categories check
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  let categoryCount = 0;
  if (hasUpper) categoryCount++;
  if (hasLower) categoryCount++;
  if (hasDigit) categoryCount++;
  if (hasSpecial) categoryCount++;

  if (requireComplexity && categoryCount < 3) {
    errors.push('Password must contain characters from at least 3 complexity groups (uppercase, lowercase, digits, special characters)');
  }

  // 4. Context Leak Validation
  if (context) {
    if (context.username && context.username.length >= 3) {
      const uLower = context.username.toLowerCase();
      if (passwordLower.includes(uLower)) {
        errors.push(`Password contains predictable user context information: username`);
      }
    }
    if (context.firstName && context.firstName.length >= 3) {
      const fLower = context.firstName.toLowerCase();
      if (passwordLower.includes(fLower)) {
        errors.push(`Password contains predictable user context information: firstName`);
      }
    }
    if (context.lastName && context.lastName.length >= 3) {
      const lLower = context.lastName.toLowerCase();
      if (passwordLower.includes(lLower)) {
        errors.push(`Password contains predictable user context information: lastName`);
      }
    }
    if (context.email) {
      const emailParts = context.email.toLowerCase().split(/[@.]/);
      for (const part of emailParts) {
        if (part.length >= 3 && passwordLower.includes(part)) {
          errors.push(`Password contains predictable user context information: email parts`);
          break;
        }
      }
    }
    if (context.birthDate) {
      const dateParts = context.birthDate.split(/[-/.]/);
      for (const part of dateParts) {
        if (part.length >= 2 && passwordLower.includes(part)) {
          errors.push(`Password contains predictable user context information: birthDate parts`);
          break;
        }
      }
    }
  }

  // 5. Repetitive and Sequential checks
  let hasRepetitive = false;
  for (let i = 0; i < password.length - 2; i++) {
    if (password[i] === password[i + 1] && password[i] === password[i + 2]) {
      hasRepetitive = true;
      break;
    }
  }
  if (hasRepetitive) {
    warnings.push('Password contains repetitive characters');
  }

  let hasSequential = false;
  for (let i = 0; i < password.length - 2; i++) {
    const code1 = password.charCodeAt(i);
    const code2 = password.charCodeAt(i + 1);
    const code3 = password.charCodeAt(i + 2);
    if ((code2 === code1 + 1 && code3 === code2 + 1) || (code2 === code1 - 1 && code3 === code2 - 1)) {
      hasSequential = true;
      break;
    }
  }
  if (hasSequential) {
    warnings.push('Password contains sequential characters');
  }

  // Calculate Shannon Entropy
  const entropy = calculateShannonEntropy(password);

  // 6. Scoring Algorithm
  let score = 0;

  // Length points (max 40)
  score += Math.min(password.length * 4, 40);

  // Complexity points (max 40)
  score += categoryCount * 10;

  // Entropy bonus (max 20)
  score += Math.min(entropy * 5, 20);

  // Apply reductions
  if (isCommon) {
    score = Math.min(score, 10);
  }
  if (password.length < minLength || password.length > 128) {
    score = Math.min(score, 5);
  }
  if (errors.some(e => e.includes('context'))) {
    score = Math.max(0, score - 30);
  }
  if (hasRepetitive) {
    score = Math.max(0, score - 15);
  }
  if (hasSequential) {
    score = Math.max(0, score - 15);
  }

  score = Math.round(score);
  score = Math.max(0, Math.min(score, 100));

  // Classify strength
  let strength: 'very_weak' | 'weak' | 'medium' | 'strong' | 'very_strong';
  if (score < 20) {
    strength = 'very_weak';
  } else if (score < 40) {
    strength = 'weak';
  } else if (score < 60) {
    strength = 'medium';
  } else if (score < 80) {
    strength = 'strong';
  } else {
    strength = 'very_strong';
  }

  return {
    valid: errors.length === 0,
    score,
    entropy,
    errors,
    warnings,
    strength
  };
}

export function generatePasswordPolicyReport(password: string, context?: PasswordContext): string {
  const result = validatePassword(password, context);
  const status = result.valid ? '✅ SECURE' : '❌ WEAK';
  return [
    `Password Assessment Report: ${status}`,
    `----------------------------------------`,
    `Strength Score: ${result.score}/100 (${result.strength.toUpperCase().replace('_', ' ')})`,
    `Shannon Entropy: ${result.entropy} bits`,
    `Validation Status: ${result.valid ? 'Pass' : 'Fail'}`,
    result.errors.length > 0 ? `Errors:\n${result.errors.map(e => `  - ${e}`).join('\n')}` : `Errors: None`,
    result.warnings.length > 0 ? `Warnings:\n${result.warnings.map(w => `  - ${w}`).join('\n')}` : `Warnings: None`,
    `----------------------------------------`
  ].join('\n');
}
