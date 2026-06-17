/**
 * Error class thrown when a deserialization or prototype pollution violation occurs.
 */
export class VibeShieldDeserializationError extends Error {
  /**
   * Creates an instance of VibeShieldDeserializationError.
   * @param message - The error message.
   */
  constructor(message: string) {
    super(`[VibeShield] Deserialization Protection: ${message}`);
    this.name = 'VibeShieldDeserializationError';
    Object.setPrototypeOf(this, VibeShieldDeserializationError.prototype);
  }
}

/**
 * Finding representing a security vulnerability detected by static analysis.
 */
export interface Finding {
  line: number;
  pattern: string;
  severity: 'critical' | 'high' | 'warning';
  suggestion: string;
  originalCode: string;
}

/**
 * Detection result containing safety assessment and specific findings.
 */
export interface DetectionResult {
  safe: boolean;
  findings: Finding[];
}

/**
 * Checks the depth of JSON structures in a text payload.
 * @param text - The raw JSON string.
 * @param maxDepth - The maximum allowed nesting depth.
 * @throws VibeShieldDeserializationError if depth limit is exceeded.
 */
function checkJsonDepth(text: string, maxDepth: number): void {
  let depth = 0;
  let maxReached = 0;
  let inString = false;
  let escape = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (escape) {
        escape = false;
      } else if (c === '\\') {
        escape = true;
      } else if (c === '"') {
        inString = false;
      }
    } else {
      if (c === '"') {
        inString = true;
      } else if (c === '{' || c === '[') {
        depth++;
        if (depth > maxReached) maxReached = depth;
        if (maxReached > maxDepth) {
          throw new VibeShieldDeserializationError(`Maximum JSON depth of ${maxDepth} exceeded.`);
        }
      } else if (c === '}' || c === ']') {
        depth--;
      }
    }
  }
}

/**
 * Custom reviver function for JSON.parse to remove prototype pollution keys.
 * @param key - The property key.
 * @param value - The property value.
 * @returns The cleaned value, or undefined if the key is prototype-polluting.
 */
export function safeJsonReviver(key: string, value: any): any {
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    return undefined;
  }
  return value;
}

/**
 * Safely parses a JSON string, enforcing nesting limits and stripping prototype pollution.
 * @param text - The JSON string to parse.
 * @param options - Configuration options such as maxDepth.
 * @returns The parsed and sanitized value.
 * @throws VibeShieldDeserializationError on nesting limit exceeded or malformed input.
 */
export function safeJsonParse<T>(text: string, options?: { maxDepth?: number }): T {
  const maxDepth = options?.maxDepth ?? 64;
  checkJsonDepth(text, maxDepth);

  try {
    const parsed = JSON.parse(text, safeJsonReviver);
    
    // Extra guard: recursively clean up objects just in case JSON.parse reviver missed anything due to platform differences
    const cleanObject = (obj: any): any => {
      if (obj === null || typeof obj !== 'object') return obj;
      if (Array.isArray(obj)) {
        return obj.map(cleanObject);
      }
      
      const clean: any = {};
      for (const k of Object.keys(obj)) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
          continue;
        }
        clean[k] = cleanObject(obj[k]);
      }
      return clean;
    };

    return cleanObject(parsed);
  } catch (e: any) {
    if (e instanceof VibeShieldDeserializationError) throw e;
    throw new VibeShieldDeserializationError(`Malformed JSON payload: ${e.message}`);
  }
}

/**
 * Statically scans code for unsafe deserialization patterns.
 * @param code - The JavaScript/TypeScript source code to scan.
 * @returns The detection results including vulnerability findings.
 */
export function detectUnsafeDeserialization(code: string): DetectionResult {
  const findings: Finding[] = [];
  if (!code) return { safe: true, findings };

  const lines = code.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];

    // Rule 1: node-serialize / serialize-to-js / funcserialize
    const libRegex = /\b(node-serialize|serialize-to-js|funcserialize)\b/;
    const libMatch = libRegex.exec(line);
    if (libMatch) {
      findings.push({
        line: lineNum,
        pattern: libMatch[1],
        severity: 'critical',
        suggestion: `Avoid using insecure deserialization library "${libMatch[1]}". Refactor to use safeJsonParse().`,
        originalCode: line.trim()
      });
    }

    // Rule 2: eval() with serialization/unserialize references
    const evalUnsafe = /\beval\s*\(\s*.*unserialize/;
    const evalMatch = evalUnsafe.exec(line);
    if (evalMatch) {
      findings.push({
        line: lineNum,
        pattern: 'eval() with unserialize',
        severity: 'critical',
        suggestion: 'Do not use eval() to execute serialized payloads.',
        originalCode: line.trim()
      });
    }
  }

  // Sort by line number
  findings.sort((a, b) => a.line - b.line);

  return {
    safe: findings.length === 0,
    findings
  };
}
