import { describe, it, expect, vi } from 'vitest';
import { validateSchema } from '../src/core/schema-validator.js';
import { validateRequest } from '../src/middleware/request-validator.js';

describe('Schema Validator Module', () => {
  describe('Root Data Validation', () => {
    it('1. should reject non-object root data (string)', () => {
      const result = validateSchema('not an object', {});
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Root data must be an object');
    });

    it('2. should reject array as root data', () => {
      const result = validateSchema([1, 2, 3], {});
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Root data must be an object');
    });

    it('3. should reject null as root data', () => {
      const result = validateSchema(null, {});
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Root data must be an object');
    });

    it('4. should reject undefined as root data', () => {
      const result = validateSchema(undefined, {});
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Root data must be an object');
    });
  });

  describe('Basic Types', () => {
    it('5. should validate type string successfully', () => {
      const schema = { name: { type: 'string' as const } };
      const result = validateSchema({ name: 'Alice' }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({ name: 'Alice' });
    });

    it('6. should reject string type when number is passed', () => {
      const schema = { name: { type: 'string' as const } };
      const result = validateSchema({ name: 123 }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Expected type string');
    });

    it('7. should trim string value when trim is true', () => {
      const schema = { name: { type: 'string' as const, trim: true } };
      const result = validateSchema({ name: '  Alice  ' }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData.name).toBe('Alice');
    });

    it('8. should validate type number successfully', () => {
      const schema = { age: { type: 'number' as const } };
      const result = validateSchema({ age: 25 }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({ age: 25 });
    });

    it('9. should reject number type when string is passed (no coercion)', () => {
      const schema = { age: { type: 'number' as const } };
      const result = validateSchema({ age: '25' }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Expected type number');
    });

    it('10. should reject NaN values as number', () => {
      const schema = { age: { type: 'number' as const } };
      const result = validateSchema({ age: NaN }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Expected type number');
    });

    it('11. should validate type boolean successfully', () => {
      const schema = { active: { type: 'boolean' as const } };
      const result = validateSchema({ active: true }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({ active: true });
    });

    it('12. should reject boolean type when non-boolean is passed', () => {
      const schema = { active: { type: 'boolean' as const } };
      const result = validateSchema({ active: 'true' }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Expected type boolean');
    });

    it('13. should validate type object successfully', () => {
      const schema = { meta: { type: 'object' as const } };
      const result = validateSchema({ meta: { key: 'value' } }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({ meta: { key: 'value' } });
    });

    it('14. should reject object type when array is passed', () => {
      const schema = { meta: { type: 'object' as const } };
      const result = validateSchema({ meta: [1, 2, 3] }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Expected type object, got array');
    });

    it('15. should validate type array successfully', () => {
      const schema = { tags: { type: 'array' as const } };
      const result = validateSchema({ tags: ['a', 'b'] }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({ tags: ['a', 'b'] });
    });

    it('16. should reject array type when non-array is passed', () => {
      const schema = { tags: { type: 'array' as const } };
      const result = validateSchema({ tags: 'not-array' }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Expected type array');
    });
  });

  describe('Required and AllowNull', () => {
    it('17. should reject missing required field', () => {
      const schema = { name: { type: 'string' as const, required: true } };
      const result = validateSchema({}, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Field is required');
    });

    it('18. should allow missing optional field', () => {
      const schema = { name: { type: 'string' as const, required: false } };
      const result = validateSchema({}, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({});
    });

    it('19. should allow null value when allowNull is true', () => {
      const schema = { name: { type: 'string' as const, allowNull: true } };
      const result = validateSchema({ name: null }, schema);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData).toEqual({ name: null });
    });

    it('20. should reject null value when allowNull is false', () => {
      const schema = { name: { type: 'string' as const, allowNull: false } };
      const result = validateSchema({ name: null }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toBe('Value cannot be null');
    });
  });

  describe('Min and Max Constraints', () => {
    it('21. should enforce min/max length on strings', () => {
      const schema = {
        name: { type: 'string' as const, min: 3, max: 6 }
      };
      
      const tooShort = validateSchema({ name: 'ab' }, schema);
      expect(tooShort.valid).toBe(false);
      expect(tooShort.errors[0].message).toBe('Length must be at least 3');

      const tooLong = validateSchema({ name: 'abcdefg' }, schema);
      expect(tooLong.valid).toBe(false);
      expect(tooLong.errors[0].message).toBe('Length must be at most 6');

      const valid = validateSchema({ name: 'abcd' }, schema);
      expect(valid.valid).toBe(true);
    });

    it('22. should enforce min/max values on numbers', () => {
      const schema = {
        age: { type: 'number' as const, min: 18, max: 99 }
      };

      const tooYoung = validateSchema({ age: 17 }, schema);
      expect(tooYoung.valid).toBe(false);
      expect(tooYoung.errors[0].message).toBe('Value must be at least 18');

      const tooOld = validateSchema({ age: 100 }, schema);
      expect(tooOld.valid).toBe(false);
      expect(tooOld.errors[0].message).toBe('Value must be at most 99');

      const valid = validateSchema({ age: 30 }, schema);
      expect(valid.valid).toBe(true);
    });

    it('23. should enforce min/max items on arrays', () => {
      const schema = {
        items: { type: 'array' as const, min: 2, max: 4 }
      };

      const tooFew = validateSchema({ items: [1] }, schema);
      expect(tooFew.valid).toBe(false);
      expect(tooFew.errors[0].message).toBe('Array must contain at least 2 items');

      const tooMany = validateSchema({ items: [1, 2, 3, 4, 5] }, schema);
      expect(tooMany.valid).toBe(false);
      expect(tooMany.errors[0].message).toBe('Array must contain at most 4 items');

      const valid = validateSchema({ items: [1, 2, 3] }, schema);
      expect(valid.valid).toBe(true);
    });
  });

  describe('Formats', () => {
    it('24. should validate email format', () => {
      const schema = { email: { type: 'string' as const, format: 'email' as const } };
      expect(validateSchema({ email: 'test@example.com' }, schema).valid).toBe(true);
      expect(validateSchema({ email: 'invalid-email' }, schema).valid).toBe(false);
    });

    it('25. should validate uuid format', () => {
      const schema = { uuid: { type: 'string' as const, format: 'uuid' as const } };
      expect(validateSchema({ uuid: '123e4567-e89b-12d3-a456-426614174000' }, schema).valid).toBe(true);
      expect(validateSchema({ uuid: 'invalid-uuid' }, schema).valid).toBe(false);
    });

    it('26. should validate url format', () => {
      const schema = { url: { type: 'string' as const, format: 'url' as const } };
      expect(validateSchema({ url: 'https://example.com/path' }, schema).valid).toBe(true);
      expect(validateSchema({ url: 'invalid-url' }, schema).valid).toBe(false);
    });

    it('27. should validate ipv4 format', () => {
      const schema = { ip: { type: 'string' as const, format: 'ipv4' as const } };
      expect(validateSchema({ ip: '192.168.1.1' }, schema).valid).toBe(true);
      expect(validateSchema({ ip: '999.999.999.999' }, schema).valid).toBe(false);
    });

    it('28. should validate ipv6 format', () => {
      const schema = { ip: { type: 'string' as const, format: 'ipv6' as const } };
      expect(validateSchema({ ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' }, schema).valid).toBe(true);
      expect(validateSchema({ ip: 'invalid-ipv6' }, schema).valid).toBe(false);
    });

    it('29. should validate phone format', () => {
      const schema = { phone: { type: 'string' as const, format: 'phone' as const } };
      expect(validateSchema({ phone: '+12345678901' }, schema).valid).toBe(true);
      expect(validateSchema({ phone: 'invalid-phone' }, schema).valid).toBe(false);
    });

    it('30. should validate date format', () => {
      const schema = { date: { type: 'string' as const, format: 'date' as const } };
      expect(validateSchema({ date: '2026-06-17' }, schema).valid).toBe(true);
      expect(validateSchema({ date: '2026-06-17T12:00:00Z' }, schema).valid).toBe(true);
      expect(validateSchema({ date: 'not-a-date' }, schema).valid).toBe(false);
    });
  });

  describe('Pattern and Enum', () => {
    it('31. should validate pattern regex matching', () => {
      const schema = { code: { type: 'string' as const, pattern: /^ABC-\d{3}$/ } };
      expect(validateSchema({ code: 'ABC-123' }, schema).valid).toBe(true);
      expect(validateSchema({ code: 'ABD-123' }, schema).valid).toBe(false);
    });

    it('32. should validate enum list constraints', () => {
      const schema = { role: { type: 'string' as const, enum: ['admin', 'user', 'guest'] } };
      expect(validateSchema({ role: 'admin' }, schema).valid).toBe(true);
      expect(validateSchema({ role: 'superadmin' }, schema).valid).toBe(false);
    });
  });

  describe('Nested Objects and Array Elements', () => {
    it('33. should recursively validate nested objects', () => {
      const schema = {
        user: {
          type: 'object' as const,
          schema: {
            profile: {
              type: 'object' as const,
              schema: {
                email: { type: 'string' as const, format: 'email' as const, required: true }
              }
            }
          }
        }
      };

      const validResult = validateSchema({
        user: { profile: { email: 'test@example.com' } }
      }, schema);
      expect(validResult.valid).toBe(true);
      expect(validResult.sanitizedData).toEqual({
        user: { profile: { email: 'test@example.com' } }
      });

      const invalidResult = validateSchema({
        user: { profile: { email: 'invalid-email' } }
      }, schema);
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.errors[0].field).toBe('user.profile.email');
    });

    it('34. should reject unknown fields in nested objects (whitelist)', () => {
      const schema = {
        user: {
          type: 'object' as const,
          schema: {
            name: { type: 'string' as const }
          }
        }
      };

      const result = validateSchema({
        user: { name: 'Bob', age: 30 }
      }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].field).toBe('user.age');
      expect(result.errors[0].message).toBe('Unknown field "age" is not allowed');
    });

    it('35. should recursively validate array elements with elementSchema', () => {
      const schema = {
        items: {
          type: 'array' as const,
          elementSchema: {
            type: 'object' as const,
            schema: {
              id: { type: 'number' as const, required: true },
              name: { type: 'string' as const }
            }
          }
        }
      };

      const validResult = validateSchema({
        items: [
          { id: 1, name: 'Item 1' },
          { id: 2, name: 'Item 2' }
        ]
      }, schema);
      expect(validResult.valid).toBe(true);

      const invalidResult = validateSchema({
        items: [
          { id: 1, name: 'Item 1' },
          { id: 'not-number', name: 'Item 2' }
        ]
      }, schema);
      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.errors[0].field).toBe('items[1].id');
    });
  });

  describe('Whitelist validation at root', () => {
    it('36. should reject unknown fields at root level', () => {
      const schema = { name: { type: 'string' as const } };
      const result = validateSchema({ name: 'Alice', unknownField: 'hello' }, schema);
      expect(result.valid).toBe(false);
      expect(result.errors[0].field).toBe('unknownField');
      expect(result.errors[0].message).toBe('Unknown field "unknownField" is not allowed');
    });
  });

  describe('Middleware Validation', () => {
    const schema = {
      id: { type: 'number' as const, required: true },
      name: { type: 'string' as const, required: true }
    };

    describe('Express Middleware', () => {
      it('37. should pass Express validation and set sanitized body', () => {
        const middleware = validateRequest(schema);
        const req = {
          params: {},
          query: {},
          body: { id: 123, name: 'Express User' }
        };
        const res = {
          status: vi.fn().mockReturnThis(),
          json: vi.fn().mockReturnThis()
        };
        const next = vi.fn();

        middleware(req, res, next);

        expect(next).toHaveBeenCalled();
        expect((req as any).sanitizedBody).toEqual({ id: 123, name: 'Express User' });
        expect(req.body).toEqual({ id: 123, name: 'Express User' });
        expect(res.status).not.toHaveBeenCalled();
      });

      it('38. should block Express requests with validation error and return status 400', () => {
        const middleware = validateRequest(schema);
        const req = {
          params: {},
          query: {},
          body: { id: 'invalid-id', name: 'Express User' }
        };
        const res = {
          status: vi.fn().mockReturnThis(),
          json: vi.fn().mockReturnThis()
        };
        const next = vi.fn();

        middleware(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
          error: 'Bad Request',
          message: 'Schema validation failed',
          errors: expect.any(Array)
        });
      });
    });

    describe('Next.js Middleware/Wrapper', () => {
      it('39. should pass Next.js validation and set sanitized body', async () => {
        const middleware = validateRequest(schema);
        const nextHandler = vi.fn().mockImplementation((req) => {
          return new Response(JSON.stringify({ success: true, user: req.sanitizedBody }), { status: 200 });
        });

        const wrappedHandler = middleware(nextHandler);

        const mockRequest = {
          url: 'https://example.com/api/user?name=Next%20User',
          clone() {
            return {
              json: async () => ({ id: 123 })
            };
          },
          json: async () => ({ id: 123 })
        };

        const response = await wrappedHandler(mockRequest);
        expect(response.status).toBe(200);

        const responseData = await response.json();
        expect(responseData.success).toBe(true);
        expect(responseData.user).toEqual({ id: 123, name: 'Next User' });
      });

      it('40. should block Next.js requests and return Response with status 400 on error', async () => {
        const middleware = validateRequest(schema);
        const nextHandler = vi.fn();

        const wrappedHandler = middleware(nextHandler);

        const mockRequest = {
          url: 'https://example.com/api/user',
          clone() {
            return {
              json: async () => ({ id: 'not-a-number', name: 'Next User' })
            };
          },
          json: async () => ({ id: 'not-a-number', name: 'Next User' })
        };

        const response = await wrappedHandler(mockRequest);
        expect(response.status).toBe(400);

        const responseData = await response.json();
        expect(responseData.error).toBe('Bad Request');
        expect(responseData.message).toBe('Schema validation failed');
        expect(responseData.errors).toBeInstanceOf(Array);
        expect(nextHandler).not.toHaveBeenCalled();
      });
    });
  });
});
