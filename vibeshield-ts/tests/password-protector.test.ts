import { describe, it, expect } from 'vitest';
import {
  validatePassword,
  calculateShannonEntropy,
  generatePasswordPolicyReport,
  COMMON_PASSWORDS
} from '../src/core/password-protector.js';
import { validatePasswordMiddleware } from '../src/middleware/password-validator.js';

describe('Password Policy Protector', () => {
  describe('calculateShannonEntropy', () => {
    it('1. should return 0 for empty string', () => {
      expect(calculateShannonEntropy('')).toBe(0);
    });

    it('2. should return 0 for single repeated character', () => {
      expect(calculateShannonEntropy('aaaaa')).toBe(0);
    });

    it('3. should calculate correct entropy for simple mixed string', () => {
      // "ab" should have 1 bit of entropy per char
      expect(calculateShannonEntropy('ab')).toBe(1);
    });

    it('4. should calculate entropy for a diverse password', () => {
      const entropy = calculateShannonEntropy('P@ssw0rd123!');
      expect(entropy).toBeGreaterThan(3);
    });
  });

  describe('validatePassword - Basic Validation & Length', () => {
    it('5. should fail with very_weak on empty password', () => {
      const result = validatePassword('');
      expect(result.valid).toBe(false);
      expect(result.score).toBe(0);
      expect(result.errors).toContain('Password cannot be empty');
      expect(result.strength).toBe('very_weak');
    });

    it('6. should fail if password exceeds 128 characters', () => {
      const longPassword = 'a'.repeat(129);
      const result = validatePassword(longPassword);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password length exceeds maximum limit of 128 characters');
    });

    it('7. should fail if password is shorter than default minLength (12)', () => {
      const result = validatePassword('Short1!');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password is too short (minimum 12 characters required)');
    });

    it('8. should respect custom minLength options', () => {
      const result = validatePassword('Short1!', undefined, { minLength: 6 });
      expect(result.valid).toBe(true);
    });
  });

  describe('validatePassword - Common Passwords Blacklist', () => {
    it('9. should fail for common password in list', () => {
      const result = validatePassword('password123');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password is one of the most commonly used passwords');
    });

    it('10. should perform case-insensitive common password check', () => {
      const result = validatePassword('PASSWORD123');
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password is one of the most commonly used passwords');
    });

    it('11. should verify COMMON_PASSWORDS size and elements', () => {
      expect(COMMON_PASSWORDS.size).toBe(191);
      expect(COMMON_PASSWORDS.has('123456')).toBe(true);
      expect(COMMON_PASSWORDS.has('security1234')).toBe(true);
    });
  });

  describe('validatePassword - Complexity Groups', () => {
    it('12. should fail if complexity requirement is unmet (only lowercase)', () => {
      const result = validatePassword('abcdefghijklmnop', undefined, { minLength: 12, requireComplexity: true });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Password must contain characters from at least 3 complexity groups (uppercase, lowercase, digits, special characters)');
    });

    it('13. should fail if complexity requirement is unmet (lowercase + uppercase)', () => {
      const result = validatePassword('Abcdefghijklmnop', undefined, { minLength: 12, requireComplexity: true });
      expect(result.valid).toBe(false);
    });

    it('14. should pass complexity with lowercase + uppercase + digits', () => {
      const result = validatePassword('Abcdefghijkl1234', undefined, { minLength: 12, requireComplexity: true });
      expect(result.valid).toBe(true);
    });

    it('15. should pass complexity with lowercase + uppercase + special', () => {
      const result = validatePassword('Abcdefghijkl!!!!', undefined, { minLength: 12, requireComplexity: true });
      expect(result.valid).toBe(true);
    });

    it('16. should pass complexity with lowercase + digits + special', () => {
      const result = validatePassword('abcdefgh1234!!!!', undefined, { minLength: 12, requireComplexity: true });
      expect(result.valid).toBe(true);
    });

    it('17. should pass complexity with uppercase + digits + special', () => {
      const result = validatePassword('ABCDEFGH1234!!!!', undefined, { minLength: 12, requireComplexity: true });
      expect(result.valid).toBe(true);
    });

    it('18. should skip complexity validation if requireComplexity is false', () => {
      const result = validatePassword('abcdefghijklmnop', undefined, { minLength: 12, requireComplexity: false });
      expect(result.valid).toBe(true);
    });
  });

  describe('validatePassword - Context Leak Checks', () => {
    const context = {
      username: 'john_doe',
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      birthDate: '1990-05-15'
    };

    it('19. should fail if password contains username', () => {
      const result = validatePassword('Passjohn_doe123!', context);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('username'))).toBe(true);
    });

    it('20. should fail if password contains firstName', () => {
      const result = validatePassword('Passjohn123!@#', context);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('firstName'))).toBe(true);
    });

    it('21. should fail if password contains lastName', () => {
      const result = validatePassword('Passdoe123!@#', context);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('lastName'))).toBe(true);
    });

    it('22. should fail if password contains email parts', () => {
      const result = validatePassword('Passexample123!', context);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('email parts'))).toBe(true);
    });

    it('23. should fail if password contains birthDate parts', () => {
      const result = validatePassword('Pass1990123!@#', context);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('birthDate parts'))).toBe(true);
    });

    it('24. should ignore short username context (less than 3 chars)', () => {
      const shortContext = { username: 'jd' };
      const result = validatePassword('Passjd123!@#', shortContext);
      expect(result.valid).toBe(true);
    });

    it('25. should ignore short email parts (less than 3 chars)', () => {
      const customContext = { email: 'ab.cd@example.com' };
      // "ab" and "cd" are < 3 characters, so they shouldn't trigger a failure
      const result = validatePassword('Passab123!@#', customContext);
      expect(result.valid).toBe(true);
    });

    it('26. should ignore short birthDate parts (less than 2 chars)', () => {
      const customContext = { birthDate: '1-2-1990' };
      // "1" and "2" are < 2 characters, so they shouldn't trigger a failure
      const result = validatePassword('Pass123!@#456', customContext);
      expect(result.valid).toBe(true);
    });
  });

  describe('validatePassword - Repetitive and Sequential Checks', () => {
    it('27. should warn on repetitive characters', () => {
      const result = validatePassword('Abc123aaa!!!');
      expect(result.warnings).toContain('Password contains repetitive characters');
    });

    it('28. should warn on sequential characters (ascending)', () => {
      const result = validatePassword('Abc123xyz!!!');
      // '123' or 'xyz' is sequential
      expect(result.warnings).toContain('Password contains sequential characters');
    });

    it('29. should warn on sequential characters (descending)', () => {
      const result = validatePassword('Abc321xyz!!!');
      // '321' is sequential
      expect(result.warnings).toContain('Password contains sequential characters');
    });

    it('30. should not warn if no sequential/repetitive characters exist', () => {
      const result = validatePassword('Ab1Cd2Ef3Gh4');
      expect(result.warnings.length).toBe(0);
    });
  });

  describe('validatePassword - Strength Scoring & Classification', () => {
    it('31. should calculate appropriate score and very_strong strength', () => {
      const result = validatePassword('Tr0ub4dor&3Secure!');
      expect(result.score).toBeGreaterThanOrEqual(80);
      expect(result.strength).toBe('very_strong');
    });

    it('32. should score common passwords very low', () => {
      const result = validatePassword('password123');
      expect(result.score).toBeLessThanOrEqual(10);
    });

    it('33. should apply penalty for context leak', () => {
      const context = { username: 'john_doe' };
      const withLeak = validatePassword('john_doePass1!', context);
      const withoutLeak = validatePassword('john_doePass1!', undefined);
      expect(withLeak.score).toBeLessThan(withoutLeak.score);
    });

    it('34. should apply penalty for repetitive characters', () => {
      const withRep = validatePassword('Pass123aaa!!!');
      const withoutRep = validatePassword('Pass123abc!!!');
      expect(withRep.score).toBeLessThan(withoutRep.score);
    });
  });

  describe('generatePasswordPolicyReport', () => {
    it('35. should generate a report string with SECURE/WEAK status', () => {
      const reportSecure = generatePasswordPolicyReport('Tr0ub4dor&3Secure!');
      expect(reportSecure).toContain('✅ SECURE');
      expect(reportSecure).toContain('Strength Score:');

      const reportWeak = generatePasswordPolicyReport('123456');
      expect(reportWeak).toContain('❌ WEAK');
      expect(reportWeak).toContain('Errors:');
    });
  });

  describe('validatePasswordMiddleware', () => {
    it('36. should behave as Express middleware: allow valid passwords', () => {
      const middleware = validatePasswordMiddleware();
      const req = {
        body: {
          password: 'Tr0ub4dor&3Secure!',
          username: 'john'
        }
      };
      let jsonCalled = false;
      let statusCode = 200;
      const res = {
        status(code: number) {
          statusCode = code;
          return this;
        },
        json(data: any) {
          jsonCalled = true;
          return this;
        }
      };
      let nextCalled = false;
      const next = () => {
        nextCalled = true;
      };

      middleware(req, res, next);
      expect(nextCalled).toBe(true);
      expect(jsonCalled).toBe(false);
    });

    it('37. should behave as Express middleware: block invalid passwords', () => {
      const middleware = validatePasswordMiddleware();
      const req = {
        body: {
          password: '123',
          username: 'john'
        }
      };
      let jsonCalled = false;
      let statusCode = 200;
      let responseBody: any = null;
      const res = {
        status(code: number) {
          statusCode = code;
          return this;
        },
        json(data: any) {
          jsonCalled = true;
          responseBody = data;
          return this;
        }
      };
      let nextCalled = false;
      const next = () => {
        nextCalled = true;
      };

      middleware(req, res, next);
      expect(nextCalled).toBe(false);
      expect(jsonCalled).toBe(true);
      expect(statusCode).toBe(400);
      expect(responseBody.error).toBe('Bad Request');
    });

    it('38. should behave as Next.js route wrapper: allow valid passwords', async () => {
      const middleware = validatePasswordMiddleware();
      const handler = async (req: any) => {
        return { ok: true };
      };
      const wrappedHandler = middleware(handler);

      const mockRequest = {
        clone() {
          return {
            async json() {
              return { password: 'Tr0ub4dor&3Secure!' };
            }
          };
        },
        async json() {
          return { password: 'Tr0ub4dor&3Secure!' };
        }
      };

      const result = await wrappedHandler(mockRequest);
      expect(result).toEqual({ ok: true });
    });

    it('39. should behave as Next.js route wrapper: block invalid passwords', async () => {
      const middleware = validatePasswordMiddleware();
      const handler = async (req: any) => {
        return { ok: true };
      };
      const wrappedHandler = middleware(handler);

      const mockRequest = {
        clone() {
          return {
            async json() {
              return { password: '123' };
            }
          };
        },
        async json() {
          return { password: '123' };
        }
      };

      const result = await wrappedHandler(mockRequest);
      expect(result).toBeInstanceOf(Response);
      expect(result.status).toBe(400);
      const body = await result.json();
      expect(body.error).toBe('Bad Request');
      expect(body.message).toBe('Password does not meet security requirements');
    });
  });
});
