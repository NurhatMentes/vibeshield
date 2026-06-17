import { describe, it, expect } from 'vitest';
import { detectRcePatterns } from '../src/core/rce-detector.js';

describe('RCE Pattern Detector', () => {
  // ── EVAL TESTS ────────────────────────────────────────────────────────
  describe('eval()', () => {
    it('should flag static eval as high severity', () => {
      const code = 'eval("1 + 1");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toEqual({
        line: 1,
        pattern: 'eval()',
        severity: 'high',
        suggestion: 'eval() is highly discouraged. Refactor to use static code structures.',
        originalCode: 'eval("***");'
      });
    });

    it('should flag dynamic eval with concatenation as critical', () => {
      const code = 'eval("1 + " + x);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('eval()');
      expect(result.findings[0].originalCode).toBe('eval("***" + x);');
    });

    it('should flag dynamic eval with template literals as critical', () => {
      const code = 'eval(`1 + ${x}`);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].originalCode).toBe('eval(`***`);');
    });

    it('should flag dynamic eval with variable as critical', () => {
      const code = 'eval(payload);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].originalCode).toBe('eval(payload);');
    });
  });

  // ── FUNCTION CONSTRUCTOR TESTS ────────────────────────────────────────
  describe('Function Constructor', () => {
    it('should flag static new Function as high severity', () => {
      const code = 'const fn = new Function("return 1;");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('Function constructor');
      expect(result.findings[0].originalCode).toBe('const fn = new Function("***");');
    });

    it('should flag static Function (without new) as high severity', () => {
      const code = 'const fn = Function("return 1;");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].originalCode).toBe('const fn = Function("***");');
    });

    it('should flag dynamic new Function with variable as critical', () => {
      const code = 'const fn = new Function("a", "b", userCode);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].originalCode).toBe('const fn = new Function("***", "***", userCode);');
    });
  });

  // ── TIMERS TESTS ──────────────────────────────────────────────────────
  describe('setTimeout and setInterval', () => {
    it('should flag setTimeout with static string literal as high severity', () => {
      const code = 'setTimeout("alert(1)", 1000);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('setTimeout() with string argument');
      expect(result.findings[0].originalCode).toBe('setTimeout("***", 1000);');
    });

    it('should flag setInterval with static string literal as high severity', () => {
      const code = 'setInterval("alert(1)", 1000);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('setInterval() with string argument');
    });

    it('should flag setTimeout with dynamic string as critical', () => {
      const code = 'setTimeout(payloadVar, 1000);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].originalCode).toBe('setTimeout(payloadVar, 1000);');
    });

    it('should allow safe arrow functions in setTimeout', () => {
      const code = 'setTimeout(() => { doSomething(); }, 1000);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should allow safe function declarations in setTimeout', () => {
      const code = 'setTimeout(function() { doSomething(); }, 1000);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });
  });

  // ── CHILD_PROCESS TESTS ───────────────────────────────────────────────
  describe('child_process methods', () => {
    it('should flag static exec as warning', () => {
      const code = 'child_process.exec("ls");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('warning');
      expect(result.findings[0].pattern).toBe('child_process.exec()');
      expect(result.findings[0].originalCode).toBe('child_process.exec("***");');
    });

    it('should flag dynamic exec as critical', () => {
      const code = 'exec("ls " + folder);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('child_process.exec() with dynamic input');
      expect(result.findings[0].originalCode).toBe('exec("***" + folder);');
    });

    it('should flag spawn with shell: true option as critical', () => {
      const code = 'spawn("ls", [], { shell: true });';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('child_process.spawn() with dynamic input');
    });

    it('should flag static spawn as warning', () => {
      const code = 'spawn("ls", ["-la"]);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('warning');
      expect(result.findings[0].pattern).toBe('child_process.spawn()');
    });

    it('should flag static execSync as warning', () => {
      const code = 'execSync("whoami");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('warning');
    });

    it('should flag dynamic execFileSync as critical', () => {
      const code = 'execFileSync(userCmd);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
    });
  });

  // ── VM MODULE TESTS ───────────────────────────────────────────────────
  describe('vm methods', () => {
    it('should flag static vm.runInContext as high severity', () => {
      const code = 'vm.runInContext("const x = 1;", context);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('vm.runInContext()');
      expect(result.findings[0].originalCode).toBe('vm.runInContext("***", context);');
    });

    it('should flag dynamic vm.runInNewContext as critical', () => {
      const code = 'runInNewContext(dynamicCode);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('vm.runInNewContext()');
    });
  });

  // ── SANDBOX ESCAPE TESTS ──────────────────────────────────────────────
  describe('Sandbox escapes', () => {
    it('should flag process.mainModule as critical', () => {
      const code = 'const m = process.mainModule;';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('process.mainModule');
      expect(result.findings[0].originalCode).toBe('const m = process.mainModule;');
    });

    it('should flag process.binding as critical', () => {
      const code = 'process.binding("fs");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('process.binding');
    });
  });

  // ── DYNAMIC REQUIRE/IMPORT TESTS ──────────────────────────────────────
  describe('Dynamic require/import', () => {
    it('should allow static require', () => {
      const code = 'const fs = require("fs");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should flag dynamic require as high severity', () => {
      const code = 'const mod = require(someVar);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('dynamic require()');
    });

    it('should allow static import()', () => {
      const code = 'import("fs");';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should flag dynamic import() as high severity', () => {
      const code = 'import(userSuppliedModule);';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].pattern).toBe('dynamic import()');
    });
  });

  // ── COMMENTS AND STRING LITERAL MASKING TESTS ─────────────────────────
  describe('Masking comments and string literals', () => {
    it('should ignore RCE patterns inside single-line comments', () => {
      const code = '// eval("doBadStuff()");\nconst x = 1;';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should ignore RCE patterns inside multi-line comments', () => {
      const code = '/*\n eval("doBadStuff()");\n*/\nconst x = 1;';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should ignore RCE patterns inside string literals', () => {
      const code = 'const myString = "eval(\'hello\')";';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should ignore RCE patterns inside template literals without interpolation', () => {
      const code = 'const myString = `eval(\'hello\')`;';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should flag RCE patterns inside template literal interpolations', () => {
      const code = 'const myString = `Some text ${eval(payload)}`;';
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].pattern).toBe('eval()');
    });
  });

  // ── MULTI-LINE AND COMPLEX SCENARIOS ──────────────────────────────────
  describe('Multi-line and complex scenarios', () => {
    it('should correctly report correct line numbers and sort findings', () => {
      const code = `
        const x = 1;
        eval("static"); // Line 3 - high
        const y = 2;
        exec("dynamic" + val); // Line 5 - critical
      `;
      const result = detectRcePatterns(code);
      expect(result.safe).toBe(false);
      expect(result.findings).toHaveLength(2);
      expect(result.findings[0].line).toBe(3);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[1].line).toBe(5);
      expect(result.findings[1].severity).toBe('critical');
    });
  });
});
