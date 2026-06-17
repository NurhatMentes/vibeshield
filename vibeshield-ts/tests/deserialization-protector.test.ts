import { describe, it, expect } from 'vitest';
import {
  safeJsonParse,
  detectUnsafeDeserialization,
  VibeShieldDeserializationError
} from '../src/core/deserialization-protector.js';
import { enforceSafeJson } from '../src/middleware/safe-parser.js';

describe('Deserialization & Prototype Pollution Protector', () => {
  describe('VibeShieldDeserializationError', () => {
    it('1. should inherit from Error and format message correctly', () => {
      const err = new VibeShieldDeserializationError('Test error');
      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe('VibeShieldDeserializationError');
      expect(err.message).toBe('[VibeShield] Deserialization Protection: Test error');
    });
  });

  describe('safeJsonParse', () => {
    it('2. should parse a simple flat JSON object', () => {
      const payload = '{"name":"VibeShield","version":1}';
      const parsed = safeJsonParse<{ name: string; version: number }>(payload);
      expect(parsed).toEqual({ name: 'VibeShield', version: 1 });
    });

    it('3. should parse a nested JSON object within depth limits', () => {
      const payload = '{"a":{"b":{"c":123}}}';
      const parsed = safeJsonParse<any>(payload);
      expect(parsed.a.b.c).toBe(123);
    });

    it('4. should strip __proto__ properties', () => {
      const payload = '{"a": 1, "__proto__": {"polluted": true}}';
      const parsed = safeJsonParse<any>(payload);
      expect(parsed.a).toBe(1);
      expect(Object.prototype.hasOwnProperty.call(parsed, '__proto__')).toBe(false);
      expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
      expect((parsed as any).polluted).toBeUndefined();
      expect((Object.prototype as any).polluted).toBeUndefined();
    });

    it('5. should strip constructor properties', () => {
      const payload = '{"constructor": {"prototype": {"polluted": true}}}';
      const parsed = safeJsonParse<any>(payload);
      expect(Object.prototype.hasOwnProperty.call(parsed, 'constructor')).toBe(false);
      expect(parsed.constructor).toBe(Object);
      expect((Object.prototype as any).polluted).toBeUndefined();
    });

    it('6. should strip prototype properties', () => {
      const payload = '{"prototype": {"polluted": true}}';
      const parsed = safeJsonParse<any>(payload);
      expect(Object.prototype.hasOwnProperty.call(parsed, 'prototype')).toBe(false);
      expect(parsed.prototype).toBeUndefined();
      expect((Object.prototype as any).polluted).toBeUndefined();
    });

    it('7. should strip prototype pollution nested inside arrays', () => {
      const payload = '[{"__proto__": {"polluted": true}}, {"constructor": {"prototype": {"polluted": true}}}]';
      const parsed = safeJsonParse<any[]>(payload);
      expect(Object.prototype.hasOwnProperty.call(parsed[0], '__proto__')).toBe(false);
      expect(Object.getPrototypeOf(parsed[0])).toBe(Object.prototype);
      expect(Object.prototype.hasOwnProperty.call(parsed[1], 'constructor')).toBe(false);
      expect(parsed[1].constructor).toBe(Object);
      expect((Object.prototype as any).polluted).toBeUndefined();
    });

    it('8. should strip prototype pollution inside deeply nested properties', () => {
      const payload = '{"level1": {"level2": {"__proto__": {"polluted": true}}}}';
      const parsed = safeJsonParse<any>(payload);
      expect(Object.prototype.hasOwnProperty.call(parsed.level1.level2, '__proto__')).toBe(false);
      expect(Object.getPrototypeOf(parsed.level1.level2)).toBe(Object.prototype);
      expect((Object.prototype as any).polluted).toBeUndefined();
    });

    it('9. should throw error for malformed JSON payloads', () => {
      const payload = '{"name": "VibeShield",';
      expect(() => safeJsonParse(payload)).toThrow(VibeShieldDeserializationError);
      expect(() => safeJsonParse(payload)).toThrow(/Malformed JSON payload/);
    });

    it('10. should allow custom maxDepth setting and succeed if depth is within limit', () => {
      const payload = '{"a":{"b":1}}'; // depth 2
      const parsed = safeJsonParse<any>(payload, { maxDepth: 2 });
      expect(parsed.a.b).toBe(1);
    });

    it('11. should throw if depth exceeds custom maxDepth limit', () => {
      const payload = '{"a":{"b":1}}'; // depth 2
      expect(() => safeJsonParse(payload, { maxDepth: 1 })).toThrow(VibeShieldDeserializationError);
      expect(() => safeJsonParse(payload, { maxDepth: 1 })).toThrow(/Maximum JSON depth of 1 exceeded/);
    });

    it('12. should throw if depth exceeds default maxDepth limit of 64', () => {
      // Create depth of 65
      let payload = '1';
      for (let i = 0; i < 65; i++) {
        payload = `{"a":${payload}}`;
      }
      expect(() => safeJsonParse(payload)).toThrow(VibeShieldDeserializationError);
      expect(() => safeJsonParse(payload)).toThrow(/Maximum JSON depth of 64 exceeded/);
    });

    it('13. should handle depth tracking correctly inside strings', () => {
      // Braces inside strings shouldn't count as depth
      const payload = '{"a": "[[[[[[[[[", "b": "}}}}}}}}" }';
      const parsed = safeJsonParse<any>(payload, { maxDepth: 2 });
      expect(parsed.a).toBe('[[[[[[[[[');
      expect(parsed.b).toBe('}}}}}}}}');
    });

    it('14. should handle escaped characters in strings correctly without getting confused about depth', () => {
      const payload = '{"a": "escape \\\" { [ quote", "b": 1}';
      const parsed = safeJsonParse<any>(payload, { maxDepth: 1 });
      expect(parsed.a).toBe('escape " { [ quote');
      expect(parsed.b).toBe(1);
    });

    it('15. should clean objects that are recursively nested in arrays', () => {
      const payload = '{"items": [[{"__proto__": {"test": 1}}]]}';
      const parsed = safeJsonParse<any>(payload);
      expect(Object.prototype.hasOwnProperty.call(parsed.items[0][0], '__proto__')).toBe(false);
      expect(Object.getPrototypeOf(parsed.items[0][0])).toBe(Object.prototype);
    });

    it('16. should handle empty or null values gracefully by throwing malformed JSON', () => {
      expect(() => safeJsonParse('')).toThrow(VibeShieldDeserializationError);
      expect(() => safeJsonParse('   ')).toThrow(VibeShieldDeserializationError);
    });
  });

  describe('enforceSafeJson Middleware helper', () => {
    it('17. should return empty object for empty or whitespace-only inputs', () => {
      expect(enforceSafeJson('')).toEqual({});
      expect(enforceSafeJson('   ')).toEqual({});
      expect(enforceSafeJson(null as any)).toEqual({});
      expect(enforceSafeJson(undefined as any)).toEqual({});
    });

    it('18. should parse valid JSON text', () => {
      const text = '{"user": "alice"}';
      expect(enforceSafeJson(text)).toEqual({ user: 'alice' });
    });

    it('19. should strip prototype pollution keys', () => {
      const text = '{"__proto__": {"admin": true}, "user": "bob"}';
      const parsed = enforceSafeJson(text);
      expect(parsed.user).toBe('bob');
      expect(Object.prototype.hasOwnProperty.call(parsed, '__proto__')).toBe(false);
      expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
      expect((Object.prototype as any).admin).toBeUndefined();
    });

    it('20. should obey the custom maxDepth parameter', () => {
      const text = '{"a":{"b":{"c":1}}}'; // depth 3
      expect(() => enforceSafeJson(text, 2)).toThrow(VibeShieldDeserializationError);
    });
  });

  describe('detectUnsafeDeserialization static scanner', () => {
    it('21. should return safe=true for code with no security issues', () => {
      const code = `
        const x = JSON.parse('{"a":1}');
        console.log(x);
      `;
      const result = detectUnsafeDeserialization(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('22. should detect "node-serialize" imports/requires', () => {
      const code = `
        const serialize = require('node-serialize');
        serialize.unserialize(payload);
      `;
      const result = detectUnsafeDeserialization(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].pattern).toBe('node-serialize');
      expect(result.findings[0].line).toBe(2);
      expect(result.findings[0].severity).toBe('critical');
    });

    it('23. should detect "serialize-to-js" library usage', () => {
      const code = `
        import serialize from 'serialize-to-js';
        const obj = serialize.deserialize(payload);
      `;
      const result = detectUnsafeDeserialization(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].pattern).toBe('serialize-to-js');
      expect(result.findings[0].line).toBe(2);
    });

    it('24. should detect "funcserialize" library usage', () => {
      const code = "const funcserialize = require('funcserialize');";
      const result = detectUnsafeDeserialization(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].pattern).toBe('funcserialize');
    });

    it('25. should detect eval() executing unserialize actions', () => {
      const code = `
        const payload = getPayload();
        eval("unserialize(" + payload + ")");
      `;
      const result = detectUnsafeDeserialization(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].pattern).toBe('eval() with unserialize');
      expect(result.findings[0].line).toBe(3);
    });

    it('26. should return multiple findings sorted by line number', () => {
      const code = `
        const serialize = require('node-serialize');
        // some comment
        eval("unserialize(data)");
        const fs = require('funcserialize');
      `;
      const result = detectUnsafeDeserialization(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(3);
      expect(result.findings[0].line).toBe(2);
      expect(result.findings[1].line).toBe(4);
      expect(result.findings[2].line).toBe(5);
    });

    it('27. should return safe=true and empty findings for empty/null code inputs', () => {
      expect(detectUnsafeDeserialization('')).toEqual({ safe: true, findings: [] });
      expect(detectUnsafeDeserialization(null as any)).toEqual({ safe: true, findings: [] });
    });

    it('28. should extract original code snippet correctly', () => {
      const code = "const serialize = require('node-serialize');";
      const result = detectUnsafeDeserialization(code);
      expect(result.findings[0].originalCode).toBe("const serialize = require('node-serialize');");
    });
  });
});
