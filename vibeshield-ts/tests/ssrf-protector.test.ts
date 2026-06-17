import { describe, it, expect } from 'vitest';
import { validateUrl } from '../src/core/ssrf-protector.js';
import { enforceSafeUrl, VibeShieldSSRFError } from '../src/middleware/ssrf-security.js';

describe('SSRF Protector', () => {
  describe('validateUrl', () => {
    // 1. Safe normal URLs
    it('should allow safe http URL', () => {
      const result = validateUrl('http://example.com');
      expect(result.safe).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should allow safe https URL with port and path', () => {
      const result = validateUrl('https://google.com:443/search?q=vibeshield');
      expect(result.safe).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    // 2. Protocols
    it('should reject ftp protocol', () => {
      const result = validateUrl('ftp://example.com');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Forbidden protocol');
    });

    it('should reject file protocol', () => {
      const result = validateUrl('file:///etc/passwd');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Forbidden protocol');
    });

    it('should reject gopher protocol', () => {
      const result = validateUrl('gopher://example.com');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Forbidden protocol');
    });

    // 3. AWS/Cloud Metadata & Link-Local IPv4
    it('should reject AWS metadata IP (169.254.169.254)', () => {
      const result = validateUrl('http://169.254.169.254/latest/meta-data/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Link-local IP address blocked');
    });

    it('should reject AWS metadata IP in decimal format', () => {
      // 169.254.169.254 in decimal is 2852039166
      const result = validateUrl('http://2852039166');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Link-local IP address blocked');
    });

    it('should reject AWS metadata IP in hex format', () => {
      const result = validateUrl('http://0xa9.0xfe.0xa9.0xfe');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Link-local IP address blocked');
    });

    it('should reject AWS metadata IP in octal format', () => {
      const result = validateUrl('http://0251.0376.0251.0376');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Link-local IP address blocked');
    });

    // 4. Localhost Variations
    it('should reject literal localhost', () => {
      const result = validateUrl('http://localhost');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Blocked loopback/unspecified hostname');
    });

    it('should reject 127.0.0.1 loopback IP', () => {
      const result = validateUrl('http://127.0.0.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IP address blocked');
    });

    it('should reject IPv6 loopback (::1)', () => {
      const result = validateUrl('http://[::1]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IPv6 address blocked');
    });

    it('should reject loopback in decimal format', () => {
      // 127.0.0.1 in decimal is 2130706433
      const result = validateUrl('http://2130706433');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IP address blocked');
    });

    it('should reject loopback in hex format', () => {
      const result = validateUrl('http://0x7f.0.0.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IP address blocked');
    });

    it('should reject loopback in octal format', () => {
      const result = validateUrl('http://0177.0.0.01');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IP address blocked');
    });

    it('should reject loopback with fewer parts (e.g. 127.1)', () => {
      const result = validateUrl('http://127.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IP address blocked');
    });

    // 5. Private IP Ranges (IPv4)
    it('should reject 10.x.y.z private IP', () => {
      const result = validateUrl('http://10.0.0.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Private IP address blocked');
    });

    it('should reject 172.16.x.y private IP', () => {
      const result = validateUrl('http://172.16.1.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Private IP address blocked');
    });

    it('should reject 192.168.x.y private IP', () => {
      const result = validateUrl('http://192.168.1.100');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Private IP address blocked');
    });

    // 6. Carrier-grade NAT (100.64.0.0/10)
    it('should reject Carrier-grade NAT IP', () => {
      const result = validateUrl('http://100.64.0.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Carrier-grade NAT IP address blocked');
    });

    // 7. Source Host Network (0.0.0.0/8)
    it('should reject unspecified IPv4 (0.0.0.0)', () => {
      const result = validateUrl('http://0.0.0.0');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Blocked loopback/unspecified hostname');
    });

    it('should reject source network host IP (0.1.2.3)', () => {
      const result = validateUrl('http://0.1.2.3');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Source/current host network IP address blocked');
    });

    // 8. Multicast & Reserved IPv4 (224.0.0.0/4 and above)
    it('should reject multicast IPv4', () => {
      const result = validateUrl('http://224.0.0.1');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Multicast/reserved IP address blocked');
    });

    it('should reject broadcast IPv4 (255.255.255.255)', () => {
      const result = validateUrl('http://255.255.255.255');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Multicast/reserved IP address blocked');
    });

    // 9. IPv6 Address Blocks (ULA, Link-Local, Multicast, Unspecified)
    it('should reject unspecified IPv6 (::)', () => {
      const result = validateUrl('http://[::]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Unspecified IPv6 address blocked');
    });

    it('should reject Link-local IPv6 (fe80::/10)', () => {
      const result = validateUrl('http://[fe80::1]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Link-local IPv6 address blocked');
    });

    it('should reject Unique Local IPv6 (ULA, fc00::/7)', () => {
      const result = validateUrl('http://[fc00::1]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Unique Local IPv6 address blocked');
    });

    it('should reject Multicast IPv6 (ff00::/8)', () => {
      const result = validateUrl('http://[ff02::1]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Multicast IPv6 address blocked');
    });

    // 10. IPv4-Mapped IPv6
    it('should reject IPv4-mapped loopback (::ffff:127.0.0.1)', () => {
      const result = validateUrl('http://[::ffff:127.0.0.1]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Loopback IP address blocked');
    });

    it('should reject IPv4-mapped private range (::ffff:10.0.0.1)', () => {
      const result = validateUrl('http://[::ffff:10.0.0.1]');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Private IP address blocked');
    });

    // 11. IDN Homograph / Script Mixing
    it('should reject mixed Latin and Cyrillic script mixing', () => {
      // Cyrillic 'е' (U+0435) instead of Latin 'e'
      const result = validateUrl('http://googlе.com');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Potential IDN homograph attack detected');
    });

    it('should reject mixed Latin and Greek script mixing', () => {
      // Greek 'ο' (U+03BF) instead of Latin 'o'
      const result = validateUrl('http://gοοgle.com');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Potential IDN homograph attack detected');
    });

    it('should allow non-mixed scripts (punycode or clean Cyrillic)', () => {
      const result = validateUrl('http://xn--d1acpjx3f.xn--p1ai');
      expect(result.safe).toBe(true);
    });

    // 12. Invalid URL formats
    it('should reject completely malformed URLs', () => {
      const result = validateUrl('not-a-url');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('Invalid URL format');
    });
  });

  describe('enforceSafeUrl and VibeShieldSSRFError', () => {
    it('should throw VibeShieldSSRFError on unsafe URLs', () => {
      expect(() => enforceSafeUrl('http://127.0.0.1')).toThrow(VibeShieldSSRFError);
    });

    it('should contain the URL and reason inside VibeShieldSSRFError', () => {
      try {
        enforceSafeUrl('http://10.0.0.1');
        throw new Error('Should have thrown an error');
      } catch (err: any) {
        expect(err).toBeInstanceOf(VibeShieldSSRFError);
        expect(err.url).toBe('http://10.0.0.1');
        expect(err.reason).toContain('Private IP address blocked');
        expect(err.message).toContain('[VibeShield] SSRF Protection: Blocked URL');
      }
    });

    it('should do nothing and pass quietly on safe URLs', () => {
      expect(() => enforceSafeUrl('https://vibeshield.security')).not.toThrow();
    });
  });
});
