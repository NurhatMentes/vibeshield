import { spawn } from 'child_process';
import { sanitizeShellInput, validateSafeCommand } from '../core/command-sanitizer.js';

/**
 * Result structure of a safe command execution.
 */
export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/**
 * Safely executes a command by validating the binary and sanitizing input arguments.
 * Forces shell: false to avoid command injection via shell execution features.
 *
 * @param command - The binary/command to run (e.g. 'ping', 'dig').
 * @param args - Array of command-line arguments.
 * @param options - Additional options to pass to spawn.
 * @param customAllowedList - Optional custom list of allowed commands.
 * @returns A promise resolving to the execution result.
 */
export function safeExec(
  command: string, 
  args: string[], 
  options: any = {}, 
  customAllowedList?: string[]
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    try {
      validateSafeCommand(command, args, customAllowedList);
      const sanitizedArgs = args.map(arg => sanitizeShellInput(arg));
      
      const spawnOpts = {
        ...options,
        shell: false // FORCE shell: false
      };
      
      const child = spawn(command, sanitizedArgs, spawnOpts);
      
      let stdout = '';
      let stderr = '';
      
      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });
      
      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });
      
      child.on('error', (err) => {
        reject(err);
      });
      
      child.on('close', (code) => {
        resolve({ stdout, stderr, code });
      });
    } catch (err) {
      reject(err);
    }
  });
}
