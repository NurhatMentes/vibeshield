/**
 * VibeShield RCE Pattern Detector — Usage Example
 *
 * This file demonstrates how to use the RCE Pattern Detector to analyze
 * source code files for potential Remote Code Execution vulnerabilities.
 *
 * Run with: npx tsx examples/rce-usage.ts
 */

import { detectRcePatterns } from '../src/core/rce-detector.js';

console.log('=============================================================');
console.log('🛡️ VIBESHIELD RCE PATTERN DETECTOR DEMO');
console.log('=============================================================\n');

// Helper to log detection results
function runAnalysis(caseName: string, code: string) {
  console.log(`--- ${caseName} ---`);
  console.log('Code to analyze:');
  console.log(code.trim().split('\n').map(l => `  | ${l}`).join('\n'));
  
  const result = detectRcePatterns(code);
  
  console.log(`Safe: ${result.safe ? '✅ Yes' : '❌ No'}`);
  if (result.findings.length > 0) {
    console.log('Findings:');
    result.findings.forEach((finding, index) => {
      console.log(`  [${index + 1}] Line ${finding.line} | Pattern: ${finding.pattern}`);
      console.log(`      Severity: ${finding.severity.toUpperCase()}`);
      console.log(`      Masked Code: ${finding.originalCode}`);
      console.log(`      Suggestion: ${finding.suggestion}`);
    });
  }
  console.log('\n');
}

// Case 1: Safe code
runAnalysis(
  'CASE 1: Safe standard code',
  `
const fs = require("fs");
setTimeout(() => {
  console.log("Safe timer executed.");
}, 1000);
  `
);

// Case 2: Static eval vs Dynamic eval
runAnalysis(
  'CASE 2: Static and Dynamic eval()',
  `
// Static eval (discouraged but not user-controlled input)
eval("const a = 1;");

// Dynamic eval (highly dangerous, critical RCE risk)
const userInput = "process.exit()";
eval("run(" + userInput + ")");
  `
);

// Case 3: Dangerous child_process commands
runAnalysis(
  'CASE 3: Child Process Execution',
  `
const { exec, spawn } = require("child_process");

// Warning: standard spawn
spawn("ls", ["-la"]);

// Critical: command built with string concatenation
exec("rm -rf " + targetDirectory);

// Critical: spawn with shell option enabled
spawn("git", ["clone", repo], { shell: true });
  `
);

// Case 4: Sandbox Escape attempt and comments
runAnalysis(
  'CASE 4: Sandbox Escape & Ignored Comments',
  `
// We should ignore commented-out issues like:
// eval(dangerousInput);

/*
  child_process.exec(userInput);
*/

// Actual escape attempt
const binding = process.binding("fs");
  `
);

console.log('=============================================================');
console.log('💡 TIP: Run this detector pre-commit or in CI pipelines to block');
console.log('   accidental introduction of dynamic code execution patterns.');
console.log('=============================================================');
