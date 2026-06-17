import pytest
from unittest.mock import patch, MagicMock
import logging

from src.command_sanitizer import (
    sanitize_shell_input,
    validate_safe_command,
    VibeShieldCommandInjectionError
)
from src.middleware.safe_exec import safe_exec


class TestCommandSanitizer:
    # ── sanitize_shell_input Tests ──────────────────────────────────────────

    def test_sanitize_shell_input_valid(self):
        """Should accept strings with only safe whitelisted characters."""
        assert sanitize_shell_input("valid-input_123.test@domain:80") == "valid-input_123.test@domain:80"

    def test_sanitize_shell_input_null_byte(self):
        """Should raise VibeShieldCommandInjectionError if a null byte is present."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("input\x00arg")
        assert "Null byte injection detected." in str(exc_info.value)

    def test_sanitize_shell_input_space(self):
        """Should raise error for inputs containing space characters."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("input arg")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_semicolon(self):
        """Should raise error for inputs containing semicolons."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("arg;command")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_pipe(self):
        """Should raise error for inputs containing pipes."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("arg|command")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_ampersand(self):
        """Should raise error for inputs containing ampersands."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("arg&command")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_newline(self):
        """Should raise error for inputs containing newlines."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("arg\ncommand")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_carriage_return(self):
        """Should raise error for inputs containing carriage returns."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("arg\rcommand")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_backtick(self):
        """Should raise error for inputs containing backticks."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("`command`")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_dollar(self):
        """Should raise error for inputs containing dollar signs."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("$VAR")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_parenthesis(self):
        """Should raise error for inputs containing parentheses."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("$(command)")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_redirection_out(self):
        """Should raise error for inputs containing output redirection."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("file.txt>out.txt")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_redirection_in(self):
        """Should raise error for inputs containing input redirection."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("file.txt<in.txt")
        assert "contains forbidden characters" in str(exc_info.value)

    def test_sanitize_shell_input_wildcard(self):
        """Should raise error for inputs containing wildcards."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            sanitize_shell_input("*.txt")
        assert "contains forbidden characters" in str(exc_info.value)

    # ── validate_safe_command Tests ─────────────────────────────────────────

    def test_validate_safe_command_allowed_default(self):
        """Should accept commands in the default allowed list."""
        # None exception is raised, command and args are valid
        validate_safe_command("ping", ["127.0.0.1"])
        validate_safe_command("dig", ["example.com"])
        validate_safe_command("git", ["clone"])

    def test_validate_safe_command_disallowed_default(self):
        """Should raise error for command not in default allowed list."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("rm", ["-rf", "tmp"])
        assert "is not in the allowed list" in str(exc_info.value)

        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("bash", ["-c", "id"])
        assert "is not in the allowed list" in str(exc_info.value)

    def test_validate_safe_command_custom_allowed(self):
        """Should respect the custom allowed commands list."""
        custom_list = ["custom_cmd", "another_cmd"]
        # Valid
        validate_safe_command("custom_cmd", [], custom_list)
        
        # Invalid
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("ping", ["127.0.0.1"], custom_list)
        assert "is not in the allowed list" in str(exc_info.value)

    def test_validate_safe_command_path_traversal_forward_slash(self):
        """Should reject commands containing forward slashes."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("/usr/bin/ping", ["127.0.0.1"])
        assert "Path injection or traversal detected" in str(exc_info.value)

    def test_validate_safe_command_path_traversal_backward_slash(self):
        """Should reject commands containing backward slashes."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("C:\\Windows\\System32\\ping", ["127.0.0.1"])
        assert "Path injection or traversal detected" in str(exc_info.value)

    def test_validate_safe_command_path_traversal_dots(self):
        """Should reject commands containing directory traversal dots."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("../ping", ["127.0.0.1"])
        assert "Path injection or traversal detected" in str(exc_info.value)

    def test_validate_safe_command_arg_traversal_dots(self):
        """Should reject command arguments containing traversal dots."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("ping", ["../etc/passwd"])
        assert "Path traversal or directory separator detected" in str(exc_info.value)

    def test_validate_safe_command_arg_traversal_forward_slash(self):
        """Should reject command arguments containing forward slashes."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("ping", ["usr/bin"])
        assert "Path traversal or directory separator detected" in str(exc_info.value)

    def test_validate_safe_command_arg_traversal_backward_slash(self):
        """Should reject command arguments containing backward slashes."""
        with pytest.raises(VibeShieldCommandInjectionError) as exc_info:
            validate_safe_command("ping", ["C:\\tmp"])
        assert "Path traversal or directory separator detected" in str(exc_info.value)

    # ── safe_exec Tests ─────────────────────────────────────────────────────

    @patch("subprocess.run")
    def test_safe_exec_calls_subprocess_correctly(self, mock_run):
        """Should execute the subprocess correctly with shell=False."""
        mock_result = MagicMock()
        mock_result.stdout = "ping response"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        response = safe_exec("ping", ["127.0.0.1"])
        
        assert response == {
            "stdout": "ping response",
            "stderr": "",
            "code": 0
        }
        mock_run.assert_called_once_with(
            ["ping", "127.0.0.1"],
            shell=False,
            capture_output=True,
            text=True
        )

    def test_safe_exec_invalid_command_throws(self):
        """Should raise validation error for a blocked binary."""
        with pytest.raises(VibeShieldCommandInjectionError):
            safe_exec("rm", ["-rf", "tmp"])

    def test_safe_exec_invalid_arg_throws(self):
        """Should raise validation error for illegal characters in arguments."""
        with pytest.raises(VibeShieldCommandInjectionError):
            safe_exec("ping", ["127.0.0.1; rm -rf /"])

    @patch("subprocess.run")
    def test_safe_exec_exception_logging(self, mock_run):
        """Should log and re-raise subprocess run exceptions."""
        mock_run.side_effect = OSError("Execution failed")
        
        with patch("logging.Logger.error") as mock_log:
            with pytest.raises(OSError):
                safe_exec("ping", ["127.0.0.1"])
            
            mock_log.assert_called_once_with(
                "[VibeShield] Command execution failed: %s",
                "Execution failed"
            )
