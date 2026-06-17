/**
 * Custom error thrown when a command injection protection validation fails.
 */
export class VibeShieldCommandInjectionError extends Error {
  constructor(message: string) {
    super(`[VibeShield] Command Injection Protection: ${message}`);
    this.name = 'VibeShieldCommandInjectionError';
    Object.setPrototypeOf(this, VibeShieldCommandInjectionError.prototype);
  }
}

const DEFAULT_ALLOWED_COMMANDS = ['ping', 'nslookup', 'dig', 'host', 'whois', 'curl', 'wget', 'git'];

/**
 * Sanitizes a single shell input argument to prevent shell metacharacter injection.
 * Checks for null byte injection and restricts characters to a safe whitelist.
 *
 * @param input - The command line input/argument to sanitize.
 * @returns The sanitized input string if valid.
 * @throws {VibeShieldCommandInjectionError} If validation fails (e.g. null bytes or forbidden characters).
 */
export function sanitizeShellInput(input: string): string {
  if (input.includes('\0')) {
    throw new VibeShieldCommandInjectionError('Null byte injection detected.');
  }
  // Whitelist: strictly alphanumeric, hyphen, underscore, dot, @, colon. No spaces, no shell metacharacters.
  const whitelist = /^[a-zA-Z0-9_\-\.@:]+$/;
  if (!whitelist.test(input)) {
    throw new VibeShieldCommandInjectionError(`Input "${input}" contains forbidden characters.`);
  }
  return input;
}

/**
 * Validates that the specified command and its arguments are safe from command injection.
 * Specifically checks for path traversal characters and validates the command against an allowed list.
 *
 * @param command - The base binary/command to run.
 * @param args - The arguments provided to the command.
 * @param customAllowedList - Optional custom list of allowed commands.
 * @throws {VibeShieldCommandInjectionError} If validation fails.
 */
export function validateSafeCommand(command: string, args: string[], customAllowedList?: string[]): void {
  const cleanCommand = command.trim();
  
  // Prevent directory / path traversal in command path
  if (cleanCommand.includes('/') || cleanCommand.includes('\\') || cleanCommand.includes('..')) {
    throw new VibeShieldCommandInjectionError(`Path injection or traversal detected in command "${command}".`);
  }

  const allowedList = customAllowedList || DEFAULT_ALLOWED_COMMANDS;
  if (!allowedList.includes(cleanCommand)) {
    throw new VibeShieldCommandInjectionError(`Command "${cleanCommand}" is not in the allowed list.`);
  }

  // Prevent path traversal in command arguments
  for (const arg of args) {
    if (arg.includes('..') || arg.includes('/') || arg.includes('\\')) {
      throw new VibeShieldCommandInjectionError(`Path traversal or directory separator detected in argument "${arg}".`);
    }
  }
}
