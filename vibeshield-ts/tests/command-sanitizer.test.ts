import { vi, describe, it, expect, beforeEach } from 'vitest';
import { sanitizeShellInput, validateSafeCommand, VibeShieldCommandInjectionError } from '../src/core/command-sanitizer.js';
import { safeExec } from '../src/middleware/safe-exec.js';
import { spawn } from 'child_process';
import { EventEmitter } from 'events';

// Mock child_process spawn
vi.mock('child_process', () => {
  return {
    spawn: vi.fn((command: string, args: string[], options: any) => {
      const child = new EventEmitter() as any;
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      
      process.nextTick(() => {
        if (command === 'ping' && args.includes('fail-arg')) {
          child.stderr.emit('data', Buffer.from('Ping error output'));
          child.emit('close', 1);
        } else if (command === 'ping') {
          child.stdout.emit('data', Buffer.from('Ping success output'));
          child.emit('close', 0);
        } else {
          child.emit('error', new Error('Spawn failed'));
        }
      });
      
      return child;
    })
  };
});

describe('Command Injection Protection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('sanitizeShellInput', () => {
    // 1. Safe domain names
    it('should allow safe domain names', () => {
      expect(sanitizeShellInput('google.com')).toBe('google.com');
    });

    // 2. Safe subdomains
    it('should allow safe subdomains', () => {
      expect(sanitizeShellInput('api.v1.domain.co.uk')).toBe('api.v1.domain.co.uk');
    });

    // 3. Safe usernames
    it('should allow safe usernames', () => {
      expect(sanitizeShellInput('john_doe')).toBe('john_doe');
    });

    // 4. Safe email addresses
    it('should allow safe email addresses', () => {
      expect(sanitizeShellInput('user@domain.com')).toBe('user@domain.com');
    });

    // 5. Safe symbols and options
    it('should allow options and safe symbols', () => {
      expect(sanitizeShellInput('-v')).toBe('-v');
      expect(sanitizeShellInput('--help')).toBe('--help');
      expect(sanitizeShellInput('@org-pkg')).toBe('@org-pkg');
      expect(sanitizeShellInput('key:value')).toBe('key:value');
    });

    // 6. Reject null byte injection
    it('should reject null byte injection', () => {
      expect(() => sanitizeShellInput('google.com\0')).toThrow(VibeShieldCommandInjectionError);
      expect(() => sanitizeShellInput('google.com\0')).toThrow('Null byte injection detected.');
    });

    // 7. Reject semicolon injection
    it('should reject semicolon injection', () => {
      expect(() => sanitizeShellInput('google.com; rm -rf /')).toThrow(VibeShieldCommandInjectionError);
    });

    // 8. Reject pipe injection
    it('should reject pipe injection', () => {
      expect(() => sanitizeShellInput('google.com | id')).toThrow(VibeShieldCommandInjectionError);
    });

    // 9. Reject subshell syntax
    it('should reject subshell syntax $(whoami)', () => {
      expect(() => sanitizeShellInput('$(whoami)')).toThrow(VibeShieldCommandInjectionError);
    });

    // 10. Reject backticks
    it('should reject backtick syntax `id`', () => {
      expect(() => sanitizeShellInput('`id`')).toThrow(VibeShieldCommandInjectionError);
    });

    // 11. Reject space characters
    it('should reject space characters', () => {
      expect(() => sanitizeShellInput('ping -c 1')).toThrow(VibeShieldCommandInjectionError);
    });

    // 12. Reject newlines
    it('should reject newline characters', () => {
      expect(() => sanitizeShellInput('google.com\nwhoami')).toThrow(VibeShieldCommandInjectionError);
    });

    // 13. Reject tabs
    it('should reject tab characters', () => {
      expect(() => sanitizeShellInput('google.com\twhoami')).toThrow(VibeShieldCommandInjectionError);
    });

    // 14. Reject other shell metacharacters
    it('should reject other metacharacters', () => {
      const meta = ['&', '&&', '||', '<', '>', '$', '*', '?', '[', ']', '(', ')', '#', '!', '`'];
      for (const char of meta) {
        expect(() => sanitizeShellInput(`arg${char}`)).toThrow(VibeShieldCommandInjectionError);
      }
    });
  });

  describe('validateSafeCommand', () => {
    // 15. Default allowed commands
    it('should allow default allowed commands', () => {
      expect(() => validateSafeCommand('ping', ['8.8.8.8'])).not.toThrow();
    });

    // 16. Other default allowed commands
    it('should allow curl and git', () => {
      expect(() => validateSafeCommand('curl', ['example.com'])).not.toThrow();
      expect(() => validateSafeCommand('git', ['status'])).not.toThrow();
    });

    // 17. Disallowed commands
    it('should reject disallowed commands', () => {
      expect(() => validateSafeCommand('rm', ['-rf', '/'])).toThrow(VibeShieldCommandInjectionError);
      expect(() => validateSafeCommand('sh', [])).toThrow(VibeShieldCommandInjectionError);
    });

    // 18. Custom allowed list
    it('should support custom allowed lists', () => {
      const customList = ['my-bin', 'another-bin'];
      expect(() => validateSafeCommand('my-bin', [], customList)).not.toThrow();
      expect(() => validateSafeCommand('ping', [], customList)).toThrow(VibeShieldCommandInjectionError);
    });

    // 19. Command path traversal (slashes)
    it('should reject command path traversal with slashes', () => {
      expect(() => validateSafeCommand('/usr/bin/ping', [])).toThrow(VibeShieldCommandInjectionError);
      expect(() => validateSafeCommand('ping/sub', [])).toThrow(VibeShieldCommandInjectionError);
    });

    // 20. Command path traversal (backslashes)
    it('should reject command path traversal with backslashes', () => {
      expect(() => validateSafeCommand('C:\\Windows\\System32\\ping', [])).toThrow(VibeShieldCommandInjectionError);
      expect(() => validateSafeCommand('ping\\sub', [])).toThrow(VibeShieldCommandInjectionError);
    });

    // 21. Arguments with directory traversal (..)
    it('should reject arguments containing ..', () => {
      expect(() => validateSafeCommand('ping', ['../../etc/passwd'])).toThrow(VibeShieldCommandInjectionError);
    });

    // 22. Arguments with directory/path separators
    it('should reject arguments containing / or \\', () => {
      expect(() => validateSafeCommand('ping', ['/etc/passwd'])).toThrow(VibeShieldCommandInjectionError);
      expect(() => validateSafeCommand('ping', ['C:\\Windows'])).toThrow(VibeShieldCommandInjectionError);
    });
  });

  describe('safeExec', () => {
    // 23. Successful execution
    it('should execute a safe command successfully', async () => {
      const result = await safeExec('ping', ['8.8.8.8']);
      expect(result).toEqual({
        stdout: 'Ping success output',
        stderr: '',
        code: 0
      });
      expect(spawn).toHaveBeenCalledWith('ping', ['8.8.8.8'], { shell: false });
    });

    // 24. Command failing exit code
    it('should handle non-zero exit codes', async () => {
      const result = await safeExec('ping', ['fail-arg']);
      expect(result).toEqual({
        stdout: '',
        stderr: 'Ping error output',
        code: 1
      });
    });

    // 25. Throw error for disallowed command
    it('should reject disallowed commands', async () => {
      await expect(safeExec('rm', ['-rf'])).rejects.toThrow(VibeShieldCommandInjectionError);
    });

    // 26. Throw error for invalid argument
    it('should reject invalid arguments', async () => {
      await expect(safeExec('ping', ['8.8.8.8; rm'])).rejects.toThrow(VibeShieldCommandInjectionError);
    });
  });
});
