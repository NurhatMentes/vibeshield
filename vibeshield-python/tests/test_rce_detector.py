import pytest
from src.rce_detector import detect_rce_patterns, mask_comments_and_strings


class TestRceDetector:
    # ── Basic and Clean Code Tests ─────────────────────────────────────
    def test_empty_code_is_safe(self):
        result = detect_rce_patterns("")
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    def test_whitespace_only_code_is_safe(self):
        result = detect_rce_patterns("   \n\n   ")
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    def test_clean_python_code_is_safe(self):
        code = """
def greet(name):
    print(f"Hello, {name}!")
    return len(name)
"""
        result = detect_rce_patterns(code)
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    # ── Comment and String Masking Tests ───────────────────────────────
    def test_commented_rce_is_safe(self):
        code = "# eval('import os')\n# os.system('ls')"
        result = detect_rce_patterns(code)
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    def test_rce_in_normal_string_is_safe(self):
        code = "query = 'SELECT * FROM users WHERE eval_code = 1'"
        result = detect_rce_patterns(code)
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    # ── Rule 1: Eval, Exec, Compile ────────────────────────────────────
    def test_eval_static_is_high(self):
        code = "eval('1 + 1')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "eval()"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "eval('***')"

    def test_eval_dynamic_is_critical(self):
        code = "eval('1 + ' + user_input)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "eval()"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "eval('***' + user_input)"

    def test_exec_static_is_high(self):
        code = "exec('import sys')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "exec()"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "exec('***')"

    def test_exec_dynamic_is_critical(self):
        code = "exec(f'import {module_name}')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "exec()"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "exec(f'*******{module_name}')"

    def test_compile_static_is_high(self):
        code = "compile('x = 1', 'test_file', 'exec')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "compile()"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "compile('***', '***', '***')"

    def test_compile_dynamic_is_critical(self):
        code = "compile(user_code, 'test_file', 'exec')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "compile()"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "compile(user_code, '***', '***')"

    # ── Rule 2: os module functions ────────────────────────────────────
    def test_os_system_static_is_high(self):
        code = "os.system('ls -la')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "os.system()"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "os.system('***')"

    def test_os_system_dynamic_is_critical(self):
        code = "os.system('rm -rf ' + target_dir)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "os.system()"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "os.system('***' + target_dir)"

    def test_os_popen_static_is_high(self):
        code = "os.popen('whoami')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "os.popen()"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "os.popen('***')"

    def test_os_popen_dynamic_is_critical(self):
        code = "os.popen(f'cat {file_path}')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "os.popen()"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "os.popen(f'****{file_path}')"

    def test_os_spawn_dynamic_is_critical(self):
        code = "os.spawnlp(os.P_WAIT, cmd, cmd, '--help')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "os.spawnlp()"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "os.spawnlp(os.P_WAIT, cmd, cmd, '***')"

    # ── Rule 3: Subprocess functions ───────────────────────────────────
    def test_subprocess_run_safe_list(self):
        code = "subprocess.run(['ls', '-la'])"
        result = detect_rce_patterns(code)
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    def test_subprocess_run_shell_true_static_is_high(self):
        code = "subprocess.run('ls -la', shell=True)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "subprocess.run(shell=True)"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "subprocess.run('***', shell=True)"

    def test_subprocess_run_shell_true_dynamic_is_critical(self):
        code = "subprocess.run('ls -la ' + path_arg, shell=True)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "subprocess.run(shell=True) with dynamic input"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "subprocess.run('***' + path_arg, shell=True)"

    def test_subprocess_run_no_shell_dynamic_is_warning(self):
        code = "subprocess.run(['ls', path_arg])"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "subprocess.run() with dynamic input"
        assert finding["severity"] == "warning"
        assert finding["original_code"] == "subprocess.run(['***', path_arg])"

    def test_subprocess_popen_shell_true_dynamic_is_critical(self):
        code = "subprocess.Popen(f'echo {message}', shell=True)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "subprocess.Popen(shell=True) with dynamic input"
        assert finding["severity"] == "critical"
        assert finding["original_code"] == "subprocess.Popen(f'*****{message}', shell=True)"

    # ── Rule 4: Sandbox Escapes ────────────────────────────────────────
    def test_import_static_is_warning(self):
        code = "__import__('os')"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "__import__()"
        assert finding["severity"] == "warning"
        assert finding["original_code"] == "__import__('***')"

    def test_import_dynamic_is_high(self):
        code = "__import__(module_var)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "__import__()"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "__import__(module_var)"

    def test_globals_is_warning(self):
        code = "globals()"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "globals()"
        assert finding["severity"] == "warning"
        assert finding["original_code"] == "globals()"

    def test_locals_is_warning(self):
        code = "locals()"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "locals()"
        assert finding["severity"] == "warning"
        assert finding["original_code"] == "locals()"

    # ── Rule 5: getattr / setattr dynamic lookup ───────────────────────
    def test_getattr_static_is_safe(self):
        code = "getattr(obj, 'attribute')"
        result = detect_rce_patterns(code)
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    def test_getattr_dynamic_is_high(self):
        code = "getattr(obj, dynamic_attr)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "dynamic getattr() attribute lookup"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "getattr(obj, dynamic_attr)"

    def test_setattr_static_is_safe(self):
        code = "setattr(obj, 'attribute', value)"
        result = detect_rce_patterns(code)
        assert result["safe"] is True
        assert len(result["findings"]) == 0

    def test_setattr_dynamic_is_high(self):
        code = "setattr(obj, dynamic_attr, value)"
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "dynamic setattr() attribute lookup"
        assert finding["severity"] == "high"
        assert finding["original_code"] == "setattr(obj, dynamic_attr, value)"

    # ── Advanced F-string Interpolation & Nested Cases ────────────────
    def test_f_string_nested_rce_is_critical(self):
        code = 'f"User output: {eval(user_code)}"'
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["pattern"] == "eval()"
        assert finding["severity"] == "critical"
        # Since eval is inside f-string interpolation, _mask_original_code might mask quotes inside it.
        assert "eval" in finding["original_code"]

    def test_multiple_findings_are_sorted_by_line(self):
        code = """
os.system('ls')
# some comment
eval(dynamic_expr)
"""
        result = detect_rce_patterns(code)
        assert result["safe"] is False
        assert len(result["findings"]) == 2
        assert result["findings"][0]["line"] == 2
        assert result["findings"][1]["line"] == 4
