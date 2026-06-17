import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("VibeShield")


def mask_comments_and_strings(code: str) -> str:
    """
    Masks Python comments and string literals in the code to assist pattern analysis.

    Supports single-line comments (#), single-line strings (', "), triple-quoted
    strings (''', \"\"\"[triple-double]), and f-string interpolation blocks ({...}).

    Args:
        code: The source code string to mask.

    Returns:
        A masked version of the source code where string literals and comments
        are replaced with spaces, preserving layout and f-string interpolation blocks.
    """
    chars = list(code)
    masked = []
    i = 0
    n = len(chars)
    state_stack = ['NORMAL']
    brace_stack = []

    while i < n:
        current_state = state_stack[-1]
        c = chars[i]
        next_c = chars[i+1] if i + 1 < n else ""
        next_2c = chars[i+2] if i + 2 < n else ""

        if current_state in ('NORMAL', 'INTERPOLATION'):
            if c == '#':
                masked.append('#')
                i += 1
                while i < n and chars[i] not in ('\n', '\r'):
                    masked.append(' ')
                    i += 1
                continue
            if c == '"' and next_c == '"' and next_2c == '"':
                is_f = i > 0 and chars[i-1].lower() == 'f'
                if is_f:
                    masked[-1] = ' '
                state_stack.append('TRIPLE_DOUBLE_F' if is_f else 'TRIPLE_DOUBLE')
                masked.extend(['"', '"', '"'])
                i += 3
                continue
            if c == "'" and next_c == "'" and next_2c == "'":
                is_f = i > 0 and chars[i-1].lower() == 'f'
                if is_f:
                    masked[-1] = ' '
                state_stack.append('TRIPLE_SINGLE_F' if is_f else 'TRIPLE_SINGLE')
                masked.extend(["'", "'", "'"])
                i += 3
                continue
            if c == '"':
                is_f = i > 0 and chars[i-1].lower() == 'f'
                if is_f:
                    masked[-1] = ' '
                state_stack.append('STRING_DOUBLE_F' if is_f else 'STRING_DOUBLE')
                masked.append('"')
                i += 1
                continue
            if c == "'":
                is_f = i > 0 and chars[i-1].lower() == 'f'
                if is_f:
                    masked[-1] = ' '
                state_stack.append('STRING_SINGLE_F' if is_f else 'STRING_SINGLE')
                masked.append("'")
                i += 1
                continue
            if state_stack.count('INTERPOLATION') > 0:
                if c == '{':
                    brace_stack[-1] += 1
                    masked.append(c)
                    i += 1
                    continue
                if c == '}':
                    if brace_stack[-1] == 0:
                        state_stack.pop()
                        brace_stack.pop()
                        masked.append(c)
                        i += 1
                        continue
                    else:
                        brace_stack[-1] -= 1
                        masked.append(c)
                        i += 1
                        continue
            masked.append(c)
            i += 1
        elif current_state == 'STRING_SINGLE':
            if c == '\\':
                masked.extend([' ', ' '])
                i += 2
            elif c == "'":
                state_stack.pop()
                masked.append(c)
                i += 1
            elif c in ('\n', '\r'):
                masked.append(c)
                i += 1
            else:
                masked.append(' ')
                i += 1
        elif current_state == 'STRING_DOUBLE':
            if c == '\\':
                masked.extend([' ', ' '])
                i += 2
            elif c == '"':
                state_stack.pop()
                masked.append(c)
                i += 1
            elif c in ('\n', '\r'):
                masked.append(c)
                i += 1
            else:
                masked.append(' ')
                i += 1
        elif current_state == 'TRIPLE_SINGLE':
            if c == '\\':
                masked.extend([' ', ' '])
                i += 2
            elif c == "'" and next_c == "'" and next_2c == "'":
                state_stack.pop()
                masked.extend(["'", "'", "'"])
                i += 3
            elif c in ('\n', '\r'):
                masked.append(c)
                i += 1
            else:
                masked.append(' ')
                i += 1
        elif current_state == 'TRIPLE_DOUBLE':
            if c == '\\':
                masked.extend([' ', ' '])
                i += 2
            elif c == '"' and next_c == '"' and next_2c == '"':
                state_stack.pop()
                masked.extend(['"', '"', '"'])
                i += 3
            elif c in ('\n', '\r'):
                masked.append(c)
                i += 1
            else:
                masked.append(' ')
                i += 1
        elif current_state in ('STRING_SINGLE_F', 'STRING_DOUBLE_F', 'TRIPLE_SINGLE_F', 'TRIPLE_DOUBLE_F'):
            is_triple = 'TRIPLE' in current_state
            quote_char = "'" if 'SINGLE' in current_state else '"'
            if c == '\\':
                masked.extend([' ', ' '])
                i += 2
            elif c == '{' and next_c != '{':
                state_stack.append('INTERPOLATION')
                brace_stack.append(0)
                masked.append('{')
                i += 1
            elif c == '{' and next_c == '{':
                masked.extend([' ', ' '])
                i += 2
            elif c == '}' and next_c == '}':
                masked.extend([' ', ' '])
                i += 2
            elif is_triple and c == quote_char and next_c == quote_char and next_2c == quote_char:
                state_stack.pop()
                masked.extend([quote_char, quote_char, quote_char])
                i += 3
            elif not is_triple and c == quote_char:
                state_stack.pop()
                masked.append(quote_char)
                i += 1
            elif c in ('\n', '\r'):
                masked.append(c)
                i += 1
            else:
                masked.append(' ')
                i += 1
    return "".join(masked)


def _extract_call_args(code: str, start_index: int) -> Optional[Dict[str, Any]]:
    """
    Extracts call arguments matching parentheses starting from start_index.

    Args:
        code: The masked or original source code.
        start_index: The starting character index of the function call name.

    Returns:
        A dictionary with keys 'full_call', 'args', and 'end_index', or None if unmatched.
    """
    open_parens = 0
    i = start_index
    n = len(code)
    while i < n and code[i] != '(':
        i += 1
    if i >= n:
        return None
    arg_start = i + 1
    open_parens = 1
    i += 1
    while i < n and open_parens > 0:
        if code[i] == '(':
            open_parens += 1
        elif code[i] == ')':
            open_parens -= 1
        if open_parens == 0:
            break
        i += 1
    if open_parens > 0:
        return None
    return {
        'full_call': code[start_index:i+1],
        'args': code[arg_start:i],
        'end_index': i
    }


def _get_line_number(code: str, index: int) -> int:
    """
    Computes the 1-based line number for a given character index in the code.

    Args:
        code: The original source code.
        index: The character index.

    Returns:
        The 1-based line number.
    """
    return len(code[:index].split('\n'))


def _mask_original_code(line: str) -> str:
    """
    Masks string literal contents with '***' while keeping f-string interpolation and structure.

    Args:
        line: A line of original source code.

    Returns:
        The line with string contents masked.
    """
    chars = list(line)
    n = len(chars)
    masked = []
    i = 0
    state_stack = ['NORMAL']
    brace_stack = []

    while i < n:
        current_state = state_stack[-1]
        c = chars[i]
        next_c = chars[i+1] if i + 1 < n else ""
        next_2c = chars[i+2] if i + 2 < n else ""

        if current_state in ('NORMAL', 'INTERPOLATION'):
            if c == '#':
                masked.append('#')
                masked.extend([' '] * (n - i - 1))
                break
            if c == '"' and next_c == '"' and next_2c == '"':
                is_f = i > 0 and chars[i-1].lower() == 'f'
                state_stack.append('TRIPLE_DOUBLE_F' if is_f else 'TRIPLE_DOUBLE')
                masked.extend(['"', '"', '"'])
                if not is_f:
                    masked.append('***')
                i += 3
                continue
            if c == "'" and next_c == "'" and next_2c == "'":
                is_f = i > 0 and chars[i-1].lower() == 'f'
                state_stack.append('TRIPLE_SINGLE_F' if is_f else 'TRIPLE_SINGLE')
                masked.extend(["'", "'", "'"])
                if not is_f:
                    masked.append('***')
                i += 3
                continue
            if c == '"':
                is_f = i > 0 and chars[i-1].lower() == 'f'
                state_stack.append('STRING_DOUBLE_F' if is_f else 'STRING_DOUBLE')
                masked.append('"')
                if not is_f:
                    masked.append('***')
                i += 1
                continue
            if c == "'":
                is_f = i > 0 and chars[i-1].lower() == 'f'
                state_stack.append('STRING_SINGLE_F' if is_f else 'STRING_SINGLE')
                masked.append("'")
                if not is_f:
                    masked.append('***')
                i += 1
                continue
            if state_stack.count('INTERPOLATION') > 0:
                if c == '{':
                    brace_stack[-1] += 1
                    masked.append(c)
                    i += 1
                    continue
                if c == '}':
                    if brace_stack[-1] == 0:
                        state_stack.pop()
                        brace_stack.pop()
                        masked.append(c)
                        i += 1
                        continue
                    else:
                        brace_stack[-1] -= 1
                        masked.append(c)
                        i += 1
                        continue
            masked.append(c)
            i += 1
        elif current_state in ('STRING_SINGLE', 'STRING_DOUBLE', 'TRIPLE_SINGLE', 'TRIPLE_DOUBLE'):
            is_triple = 'TRIPLE' in current_state
            quote_char = "'" if 'SINGLE' in current_state else '"'
            if c == '\\':
                i += 2
            elif is_triple and c == quote_char and next_c == quote_char and next_2c == quote_char:
                state_stack.pop()
                masked.extend([quote_char, quote_char, quote_char])
                i += 3
            elif not is_triple and c == quote_char:
                state_stack.pop()
                masked.append(quote_char)
                i += 1
            else:
                i += 1
        elif current_state in ('STRING_SINGLE_F', 'STRING_DOUBLE_F', 'TRIPLE_SINGLE_F', 'TRIPLE_DOUBLE_F'):
            is_triple = 'TRIPLE' in current_state
            quote_char = "'" if 'SINGLE' in current_state else '"'
            if c == '\\':
                masked.extend([' ', ' '])
                i += 2
            elif c == '{' and next_c != '{':
                state_stack.append('INTERPOLATION')
                brace_stack.append(0)
                masked.append('{')
                i += 1
            elif c == '{' and next_c == '{':
                masked.extend(['*', '*'])
                i += 2
            elif c == '}' and next_c == '}':
                masked.extend(['*', '*'])
                i += 2
            elif is_triple and c == quote_char and next_c == quote_char and next_2c == quote_char:
                state_stack.pop()
                masked.extend([quote_char, quote_char, quote_char])
                i += 3
            elif not is_triple and c == quote_char:
                state_stack.pop()
                masked.append(quote_char)
                i += 1
            elif c in ('\n', '\r'):
                masked.append(c)
                i += 1
            else:
                masked.append('*')
                i += 1

    return "".join(masked)


def _is_dynamic(args: str) -> bool:
    """
    Checks if the function arguments contain dynamic operations.

    Args:
        args: The string of extracted arguments.

    Returns:
        True if the arguments contain variable names, concatenations, or formatting.
    """
    trimmed = args.strip()
    if not trimmed:
        return False
    # If it is a simple single string literal (after masking, has space or empty inside matching quotes)
    static_patterns = [
        r"^(['\"])\s*\1$",
        r"^([\"']{3})\s*\1$"
    ]
    if any(re.match(p, trimmed) for p in static_patterns):
        return False
    # If it contains variable lookup, format operations or concatenations
    if '+' in trimmed or '{' in trimmed or '%' in trimmed:
        return True
    # Strip quotes
    clean = re.sub(r'([\'"])\s*\1', '', trimmed)
    clean = re.sub(r'([\'"]{3})\s*\1', '', clean)
    if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*', clean):
        return True
    return False


def _get_positional_args(args: str) -> List[str]:
    """
    Parses the arguments string into individual arguments, filtering out keyword arguments.

    Args:
        args: The string of arguments inside call parentheses.

    Returns:
        A list of positional argument strings.
    """
    i = 0
    n = len(args)
    parens = 0
    brackets = 0
    braces = 0
    arg_start = 0
    parts = []
    while i < n:
        c = args[i]
        if c == '(':
            parens += 1
        elif c == ')':
            parens -= 1
        elif c == '[':
            brackets += 1
        elif c == ']':
            brackets -= 1
        elif c == '{':
            braces += 1
        elif c == '}':
            braces -= 1
        elif c == ',' and parens == 0 and brackets == 0 and braces == 0:
            parts.append(args[arg_start:i].strip())
            arg_start = i + 1
        i += 1
    if arg_start < n:
        parts.append(args[arg_start:].strip())

    positional = []
    for part in parts:
        if not part:
            continue
        # Filter out keyword arguments (e.g., shell=True)
        if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s*=(?!=)', part):
            continue
        positional.append(part)
    return positional


def detect_rce_patterns(code: str) -> Dict[str, Any]:
    """
    Analyzes Python source code for Remote Code Execution (RCE) patterns.

    Detects eval, exec, compile, dangerous os/subprocess usage, and sandbox escapes.

    Args:
        code: The Python source code to analyze.

    Returns:
        A dictionary containing "safe" (bool) and "findings" (list of dicts).
    """
    findings = []
    if not code:
        return {"safe": True, "findings": findings}

    masked = mask_comments_and_strings(code)
    lines = code.split('\n')

    def add_finding(index: int, pattern: str, severity: str, suggestion: str):
        line_num = _get_line_number(code, index)
        original_line = lines[line_num - 1] if line_num - 1 < len(lines) else ''
        findings.append({
            "line": line_num,
            "pattern": pattern,
            "severity": severity,
            "suggestion": suggestion,
            "original_code": _mask_original_code(original_line.strip())
        })

    # Rule 1: eval(...) / exec(...) / compile(...)
    for func in ('eval', 'exec', 'compile'):
        pattern_regex = re.compile(rf'\b{func}\s*(?=\()')
        for match in pattern_regex.finditer(masked):
            call = _extract_call_args(masked, match.start())
            if call:
                pos_args = _get_positional_args(call['args'])
                dynamic = any(_is_dynamic(arg) for arg in pos_args) if pos_args else False
                add_finding(
                    match.start(),
                    f"{func}()",
                    "critical" if dynamic else "high",
                    f"Avoid using {func}(). Use safe parsers or standard operations instead."
                )

    # Rule 2: os.system / os.popen / os.spawn* / os.exec*
    os_funcs = (
        'system', 'popen', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
        'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'execl', 'execle',
        'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe'
    )
    for func in os_funcs:
        pattern_regex = re.compile(rf'\b(os\.)?{func}\s*(?=\()')
        for match in pattern_regex.finditer(masked):
            call = _extract_call_args(masked, match.start())
            if call:
                pos_args = _get_positional_args(call['args'])
                dynamic = any(_is_dynamic(arg) for arg in pos_args) if pos_args else False
                add_finding(
                    match.start(),
                    f"os.{func}()",
                    "critical" if dynamic else "high",
                    f"os.{func}() execution is unsafe. Use subprocess module with shell=False and argument arrays instead."
                )

    # Rule 3: subprocess
    sub_funcs = ('run', 'Popen', 'call', 'check_output', 'check_call')
    for func in sub_funcs:
        pattern_regex = re.compile(rf'\b(subprocess\.)?{func}\s*(?=\()')
        for match in pattern_regex.finditer(masked):
            call = _extract_call_args(masked, match.start())
            if call:
                pos_args = _get_positional_args(call['args'])
                dynamic = any(_is_dynamic(arg) for arg in pos_args) if pos_args else False
                has_shell_true = bool(re.search(r'\bshell\s*=\s*True\b', call['args']))
                if has_shell_true and dynamic:
                    add_finding(
                        match.start(),
                        f"subprocess.{func}(shell=True) with dynamic input",
                        "critical",
                        "CRITICAL: Running subprocess with shell=True and dynamic arguments is highly vulnerable to command injection. Avoid shell=True and pass command arguments as a list."
                    )
                elif has_shell_true:
                    add_finding(
                        match.start(),
                        f"subprocess.{func}(shell=True)",
                        "high",
                        "subprocess with shell=True is dangerous. Disable shell mode and pass arguments as a list."
                    )
                elif dynamic:
                    add_finding(
                        match.start(),
                        f"subprocess.{func}() with dynamic input",
                        "warning",
                        "Dynamic subprocess inputs should be sanitised and validated before execution."
                    )

    # Rule 4: Sandbox escapes (__import__, globals, locals)
    for func in ('__import__',):
        pattern_regex = re.compile(rf'\b{func}\s*(?=\()')
        for match in pattern_regex.finditer(masked):
            call = _extract_call_args(masked, match.start())
            if call:
                pos_args = _get_positional_args(call['args'])
                dynamic = any(_is_dynamic(arg) for arg in pos_args) if pos_args else False
                add_finding(
                    match.start(),
                    "__import__()",
                    "high" if dynamic else "warning",
                    "Avoid dynamic imports with __import__(). Use importlib instead."
                )

    for func in ('globals', 'locals'):
        pattern_regex = re.compile(rf'\b{func}\s*(?=\()')
        for match in pattern_regex.finditer(masked):
            add_finding(
                match.start(),
                f"{func}()",
                "warning",
                f"Avoid using {func}() to prevent dynamic variable access or modification."
            )

    # Rule 5: getattr/setattr dynamic attribute lookup on variables
    for func in ('getattr', 'setattr'):
        pattern_regex = re.compile(rf'\b{func}\s*(?=\()')
        for match in pattern_regex.finditer(masked):
            call = _extract_call_args(masked, match.start())
            if call:
                pos_args = _get_positional_args(call['args'])
                if len(pos_args) >= 2:
                    second_arg = pos_args[1]
                    if _is_dynamic(second_arg):
                        add_finding(
                            match.start(),
                            f"dynamic {func}() attribute lookup",
                            "high",
                            f"Dynamic attribute resolution using {func}() with variables can be abused. Restrict attribute names using a whitelist."
                        )

    findings.sort(key=lambda x: x['line'])
    return {"safe": len(findings) == 0, "findings": findings}
