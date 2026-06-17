export interface Finding {
  line: number;
  pattern: string;
  severity: 'critical' | 'high' | 'warning';
  suggestion: string;
  originalCode: string;
}

export interface DetectionResult {
  safe: boolean;
  findings: Finding[];
}

/**
 * State machine that masks comment bodies and string literals into spaces,
 * keeping length, index, newlines, and template literal interpolations intact.
 *
 * @param code - The raw source code to mask.
 * @returns The masked source code.
 */
function maskCommentsAndStrings(code: string): string {
  const chars = code.split('');
  const masked: string[] = [];
  let i = 0;
  
  const stateStack: string[] = ['NORMAL'];
  const braceStack: number[] = [];
  
  while (i < chars.length) {
    const currentState = stateStack[stateStack.length - 1];
    const c = chars[i];
    const next = chars[i + 1];
    
    if (currentState === 'NORMAL' || currentState === 'TEMPLATE_INTERPOLATION') {
      if (c === '/' && next === '/') {
        masked.push('/', '/');
        i += 2;
        while (i < chars.length && chars[i] !== '\n' && chars[i] !== '\r') {
          masked.push(' ');
          i++;
        }
        continue;
      }
      if (c === '/' && next === '*') {
        masked.push('/', '*');
        i += 2;
        while (i < chars.length && !(chars[i] === '*' && chars[i + 1] === '/')) {
          const char = chars[i];
          if (char === '\n' || char === '\r') {
            masked.push(char);
          } else {
            masked.push(' ');
          }
          i++;
        }
        if (i < chars.length) {
          masked.push('*', '/');
          i += 2;
        }
        continue;
      }
      if (c === "'") {
        stateStack.push('STRING_SINGLE');
        masked.push(c);
        i++;
        continue;
      }
      if (c === '"') {
        stateStack.push('STRING_DOUBLE');
        masked.push(c);
        i++;
        continue;
      }
      if (c === '`') {
        stateStack.push('STRING_TEMPLATE');
        masked.push(c);
        i++;
        continue;
      }
      if (c === '}' && stateStack.includes('TEMPLATE_INTERPOLATION')) {
        if (braceStack[braceStack.length - 1] === 0) {
          stateStack.pop();
          braceStack.pop();
          masked.push(c);
          i++;
          continue;
        } else {
          braceStack[braceStack.length - 1]--;
          masked.push(c);
          i++;
          continue;
        }
      }
      if (c === '{' && stateStack.includes('TEMPLATE_INTERPOLATION')) {
        braceStack[braceStack.length - 1]++;
        masked.push(c);
        i++;
        continue;
      }
      
      masked.push(c);
      i++;
    } else if (currentState === 'STRING_SINGLE') {
      if (c === '\\') {
        masked.push(' ', ' ');
        i += 2;
      } else if (c === "'") {
        stateStack.pop();
        masked.push(c);
        i++;
      } else if (c === '\n' || c === '\r') {
        masked.push(c);
        i++;
      } else {
        masked.push(' ');
        i++;
      }
    } else if (currentState === 'STRING_DOUBLE') {
      if (c === '\\') {
        masked.push(' ', ' ');
        i += 2;
      } else if (c === '"') {
        stateStack.pop();
        masked.push(c);
        i++;
      } else if (c === '\n' || c === '\r') {
        masked.push(c);
        i++;
      } else {
        masked.push(' ');
        i++;
      }
    } else if (currentState === 'STRING_TEMPLATE') {
      if (c === '\\') {
        masked.push(' ', ' ');
        i += 2;
      } else if (c === '$' && next === '{') {
        stateStack.push('TEMPLATE_INTERPOLATION');
        braceStack.push(0);
        masked.push('$', '{');
        i += 2;
      } else if (c === '`') {
        stateStack.pop();
        masked.push(c);
        i++;
      } else if (c === '\n' || c === '\r') {
        masked.push(c);
        i++;
      } else {
        masked.push(' ');
        i++;
      }
    }
  }
  return masked.join('');
}

/**
 * Parses function arguments matching opening/closing parentheses.
 *
 * @param code - The source code.
 * @param startIndex - The start index of the call statement.
 * @returns Object with full call, args string, and end index, or null.
 */
function extractCallArgs(code: string, startIndex: number): { fullCall: string; args: string; endIndex: number } | null {
  let openParens = 0;
  let i = startIndex;
  while (i < code.length && code[i] !== '(') {
    i++;
  }
  if (i >= code.length) return null;
  const argStart = i + 1;
  openParens = 1;
  i++;
  while (i < code.length && openParens > 0) {
    if (code[i] === '(') openParens++;
    else if (code[i] === ')') openParens--;
    if (openParens === 0) break;
    i++;
  }
  if (openParens > 0) return null;
  return {
    fullCall: code.substring(startIndex, i + 1),
    args: code.substring(argStart, i),
    endIndex: i
  };
}

/**
 * Returns the 1-based line number for a given character index.
 *
 * @param code - The source code.
 * @param index - Character index.
 * @returns 1-based line number.
 */
function getLineNumber(code: string, index: number): number {
  return code.substring(0, index).split('\n').length;
}

/**
 * Replaces string content inside single, double, backtick quotes with '***' to mask secrets.
 *
 * @param line - The original line of code.
 * @returns The masked line of code.
 */
function maskOriginalCode(line: string): string {
  return line
    .replace(/(["'])(?:(?=(\\?))\2.)*?\1/g, '$1***$1')
    .replace(/(`)(?:(?=(\\?))\2.)*?`/g, '$1***$1');
}

/**
 * Checks if the extracted argument expression is dynamic.
 *
 * @param args - The arguments string.
 * @returns True if the argument is dynamic, false otherwise.
 */
function isDynamic(args: string): boolean {
  const trimmed = args.trim();
  if (!trimmed) return false;
  // If it's a simple single string literal, e.g. "foo", 'foo', `foo`
  // After masking, the contents inside quotes are just spaces.
  // Check if it matches exactly a single quoted/backticked string consisting only of spaces/empty
  const staticPattern = /^(['"`])\s*\1$/;
  if (staticPattern.test(trimmed)) return false;
  // If it contains a plus sign outside quotes or a variable, it is dynamic.
  // In masked code, any non-space/non-operator word character outside quotes indicates a variable.
  // We can check if there are variable names or interpolation syntax
  if (trimmed.includes('+') || trimmed.includes('${')) return true;
  // Check for any unquoted identifier word character (excluding numeric constants)
  const clean = trimmed.replace(/['"`]\s*['"`]/g, '');
  if (/[a-zA-Z_$][a-zA-Z0-9_$]*/.test(clean)) return true;
  return false;
}

/**
 * Scans code for Remote Code Execution (RCE) patterns.
 *
 * @param code - The source code to scan.
 * @returns DetectionResult with safety flag and details of findings.
 */
export function detectRcePatterns(code: string): DetectionResult {
  const findings: Finding[] = [];
  if (!code) return { safe: true, findings };

  const masked = maskCommentsAndStrings(code);
  const lines = code.split('\n');

  // Helper to add findings
  const addFinding = (index: number, pattern: string, severity: 'critical' | 'high' | 'warning', suggestion: string) => {
    const lineNum = getLineNumber(code, index);
    const originalLine = lines[lineNum - 1] || '';
    findings.push({
      line: lineNum,
      pattern,
      severity,
      suggestion,
      originalCode: maskOriginalCode(originalLine.trim())
    });
  };

  // Rule 1: eval(...)
  const evalRegex = /\beval\s*(?=\()/g;
  let match;
  while ((match = evalRegex.exec(masked)) !== null) {
    const call = extractCallArgs(masked, match.index);
    if (call) {
      const dynamic = isDynamic(call.args);
      addFinding(
        match.index,
        'eval()',
        dynamic ? 'critical' : 'high',
        dynamic 
          ? 'Avoid dynamic code evaluation with eval(). Use safe parsing or explicit function mappings instead.'
          : 'eval() is highly discouraged. Refactor to use static code structures.'
      );
    }
  }

  // Rule 2: Function constructor / new Function
  const funcRegex = /\b(new\s+)?Function\s*(?=\()/g;
  while ((match = funcRegex.exec(masked)) !== null) {
    const call = extractCallArgs(masked, match.index);
    if (call) {
      const dynamic = isDynamic(call.args);
      addFinding(
        match.index,
        'Function constructor',
        dynamic ? 'critical' : 'high',
        dynamic
          ? 'Avoid dynamic code generation via Function constructor.'
          : 'Function constructor is discouraged. Use standard function declarations instead.'
      );
    }
  }

  // Rule 3: setTimeout/setInterval with string arg
  const timerRegex = /\b(setTimeout|setInterval)\s*(?=\()/g;
  while ((match = timerRegex.exec(masked)) !== null) {
    const call = extractCallArgs(masked, match.index);
    if (call) {
      // Get the first argument
      const firstArg = call.args.split(',')[0].trim();
      const startsWithQuote = /^['"`]/.test(firstArg);
      const dynamic = isDynamic(firstArg);
      const isArrowOrFunction = firstArg.includes('=>') || /^\bfunction\b/.test(firstArg);
      if (!isArrowOrFunction && (startsWithQuote || dynamic)) {
        addFinding(
          match.index,
          `${match[1]}() with string argument`,
          dynamic ? 'critical' : 'high',
          'Pass a function reference or arrow function to setTimeout/setInterval instead of a string literal.'
        );
      }
    }
  }

  // Rule 4: child_process methods
  const childProcRegex = /\b(child_process\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*(?=\()/g;
  while ((match = childProcRegex.exec(masked)) !== null) {
    const call = extractCallArgs(masked, match.index);
    if (call) {
      const firstArg = call.args.split(',')[0].trim();
      const dynamic = isDynamic(firstArg);
      
      // Also check if options object has shell: true
      const hasShellTrue = /\bshell\s*:\s*true\b/i.test(call.args);

      if (dynamic || hasShellTrue) {
        addFinding(
          match.index,
          `child_process.${match[2]}() with dynamic input`,
          'critical',
          'Never execute commands constructed from dynamic user inputs. Use spawn/execFile with an array of arguments, and ensure input is validated.'
        );
      } else {
        addFinding(
          match.index,
          `child_process.${match[2]}()`,
          'warning',
          'Ensure command execution parameters are static and do not accept untrusted input.'
        );
      }
    }
  }

  // Rule 5: vm methods
  const vmRegex = /\b(vm\.)?(runInNewContext|runInContext|runInThisContext|Script)\s*(?=\()/g;
  while ((match = vmRegex.exec(masked)) !== null) {
    const call = extractCallArgs(masked, match.index);
    if (call) {
      const firstArg = call.args.split(',')[0].trim();
      const dynamic = isDynamic(firstArg);
      addFinding(
        match.index,
        `vm.${match[2]}()`,
        dynamic ? 'critical' : 'high',
        dynamic
          ? 'Avoid dynamic code execution in VM context with untrusted inputs.'
          : 'VM code execution should be restricted to trusted templates.'
      );
    }
  }

  // Rule 6: Sandbox escapes (process.mainModule / process.binding)
  const escapeRegex = /\bprocess\.(mainModule|binding|_getActiveRequests|_getActiveHandles)\b/g;
  while ((match = escapeRegex.exec(masked)) !== null) {
    addFinding(
      match.index,
      `process.${match[1]}`,
      'critical',
      'Access to process internals is a security risk and indicates a sandbox escape attempt.'
    );
  }

  // Rule 7: Dynamic require/import
  const importRegex = /\b(require|import)\s*(?=\()/g;
  while ((match = importRegex.exec(masked)) !== null) {
    const call = extractCallArgs(masked, match.index);
    if (call) {
      const dynamic = isDynamic(call.args);
      if (dynamic) {
        addFinding(
          match.index,
          `dynamic ${match[1]}()`,
          'high',
          'Avoid dynamic require/import statements. Use static imports or a whitelist of allowed modules.'
        );
      }
    }
  }

  // Sort findings by line number
  findings.sort((a, b) => a.line - b.line);

  return {
    safe: findings.length === 0,
    findings
  };
}
