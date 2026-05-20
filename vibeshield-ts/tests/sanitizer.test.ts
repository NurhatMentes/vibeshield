import { describe, it, expect } from 'vitest';
import { sanitize, sanitizeString, sanitizeUrl } from '../src/core/sanitizer.js';

describe('Sanitizer Module', () => {
  describe('sanitizeString', () => {
    it('should strip script tags and their contents', () => {
      const input = 'Hello <script>alert("xss")</script> World';
      expect(sanitizeString(input)).toBe('Hello  World');
    });

    it('should strip general HTML tags', () => {
      const input = '<div>Hello <b>World</b></div>';
      // Angle brackets get escaped or stripped
      // Under our design: tags are stripped first, then leftover brackets are escaped.
      // So '<div>Hello <b>World</b></div>' -> 'Hello World'
      expect(sanitizeString(input)).toBe('Hello World');
    });

    it('should escape single quotes and strip comments (SQLi)', () => {
      const sqlPayload = "1' OR 1=1 --";
      // Single quotes become double single quotes: 1'' OR 1=1 __
      expect(sanitizeString(sqlPayload)).toBe("1'' OR 1=1 __");
    });

    it('should neutralize block comments in SQL', () => {
      const input = 'SELECT /* inline */ * FROM users';
      expect(sanitizeString(input)).toBe('SELECT /+ inline +/ * FROM users');
    });

    it('should block javascript: protocols', () => {
      const input = 'javascript:alert(1)';
      expect(sanitizeString(input)).toBe('unsafe-protocol:alert(1)');
    });
  });

  describe('sanitize (Deep Sanitization)', () => {
    it('should recursively sanitize arrays and nested objects', () => {
      const input = {
        name: '<b>John</b>',
        hobbies: ['<script>alert(1)</script>', 'reading'],
        nested: {
          bio: "I'm a developer",
        },
      };

      const result = sanitize(input);

      expect(result.name).toBe('John');
      expect(result.hobbies[0]).toBe('');
      expect(result.hobbies[1]).toBe('reading');
      expect(result.nested.bio).toBe("I''m a developer");
    });

    it('should strip NoSQL keys starting with $', () => {
      const input = {
        username: 'john_doe',
        password: {
          $ne: 'secret',
        },
        profile: {
          name: 'John',
          $where: 'some js',
        },
      };

      const result = sanitize(input);

      expect(result.username).toBe('john_doe');
      expect(result.password).toEqual({}); // $ne is stripped
      expect(result.profile.name).toBe('John');
      expect(result.profile.$where).toBeUndefined(); // $where is stripped
    });

    it('should pass Dates and RegExps through as-is', () => {
      const date = new Date();
      const regex = /test/g;
      const input = { date, regex };
      const result = sanitize(input);
      expect(result.date).toBe(date);
      expect(result.regex).toBe(regex);
    });
  });

  describe('sanitizeUrl', () => {
    it('should sanitize query parameters in URL strings', () => {
      const url = 'https://example.com/api?user=<b>admin</b>&role=user&id[$ne]=5';
      const cleanUrl = sanitizeUrl(url);
      
      const parsed = new URL(cleanUrl);
      expect(parsed.searchParams.get('user')).toBe('admin');
      expect(parsed.searchParams.get('role')).toBe('user');
      expect(parsed.searchParams.get('id[$ne]')).toBeNull(); // stripped due to $ in parameter key
    });
  });
});
