/**
 * VibeShield Command Injection Protection — Usage Example
 *
 * This file demonstrates how to use the Command Injection Protection utilities and
 * the secure safeExec wrapper to safely run external binaries.
 *
 * Run with: npx tsx examples/command-usage.ts
 */

import {
  sanitizeShellInput,
  validateSafeCommand,
  safeExec,
  VibeShieldCommandInjectionError
} from '../src/index.js';

console.log('=============================================================');
console.log('🛡️ VIBESHIELD COMMAND INJECTION PROTECTION DEMO');
console.log('=============================================================\n');

// 1. Sanitize Shell Input
console.log('--- 1. Sanitizing Arguments ---');
const inputs = [
  'google.com',
  'api.v1.host.org',
  '--help',
  '-v',
  'google.com; rm -rf /',
  'google.com | id',
  '$(whoami)',
  'google.com\0',
  'google.com\nwhoami'
];

for (const input of inputs) {
  try {
    const sanitized = sanitizeShellInput(input);
    console.log(`✅ Input: "${input}" -> Sanitized: "${sanitized}"`);
  } catch (error) {
    if (error instanceof VibeShieldCommandInjectionError) {
      console.log(`❌ Input: "${input}" -> Rejected: ${error.message}`);
    } else {
      console.log(`💥 Unknown Error: ${(error as any).message}`);
    }
  }
}
console.log();

// 2. Validate Command & Arguments
console.log('--- 2. Validating Commands & Arguments ---');
const commandScenarios = [
  { command: 'ping', args: ['8.8.8.8'] },
  { command: 'rm', args: ['-rf', '/'] },
  { command: 'ping', args: ['../../etc/passwd'] },
  { command: '/usr/bin/ping', args: ['8.8.8.8'] },
  { command: 'curl', args: ['example.com'] },
  { command: 'git', args: ['status'] }
];

for (const scenario of commandScenarios) {
  try {
    validateSafeCommand(scenario.command, scenario.args);
    console.log(`✅ Safe Command: "${scenario.command} ${scenario.args.join(' ')}"`);
  } catch (error) {
    if (error instanceof VibeShieldCommandInjectionError) {
      console.log(`❌ Unsafe Command: "${scenario.command} ${scenario.args.join(' ')}" -> Rejected: ${error.message}`);
    } else {
      console.log(`💥 Unknown Error: ${(error as any).message}`);
    }
  }
}
console.log();

// 3. Executing commands safely
console.log('--- 3. Executing Commands Safely ---');

async function runDemo() {
  // We can try to execute a safe ping command
  // On Windows, the default allowed ping might run. Let's try to execute a short ping.
  const target = '127.0.0.1';
  console.log(`Executing safe command: ping ${target}`);
  try {
    const result = await safeExec('ping', [target]);
    console.log(`✅ Execution Completed (exit code: ${result.code})`);
    console.log(`stdout:\n${result.stdout}`);
  } catch (error) {
    console.log(`❌ Execution failed: ${(error as any).message}`);
  }

  console.log('\nTrying to execute a blocked command: rm -rf /');
  try {
    await safeExec('rm', ['-rf', '/']);
    console.log('✅ Executed? (Should not happen!)');
  } catch (error) {
    if (error instanceof VibeShieldCommandInjectionError) {
      console.log(`❌ Successfully Blocked: ${error.message}`);
    } else {
      console.log(`💥 Unknown Error: ${(error as any).message}`);
    }
  }

  console.log('\n=============================================================');
  console.log('💡 TIP: Use safeExec() to invoke binaries with shell: false.');
  console.log('   Always filter commands through validateSafeCommand().');
  console.log('=============================================================');
}

runDemo();
