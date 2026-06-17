import re

class VibeShieldCommandInjectionError(ValueError):
    """Exception raised when a command injection or unsafe execution condition is detected."""
    def __init__(self, message: str):
        super().__init__(f"[VibeShield] Command Injection Protection: {message}")
        self.message = message

DEFAULT_ALLOWED_COMMANDS = ['ping', 'nslookup', 'dig', 'host', 'whois', 'curl', 'wget', 'git']

def sanitize_shell_input(input_str: str) -> str:
    """
    Sanitizes a single shell input argument to prevent injection.

    Args:
        input_str: The input argument string to sanitize.

    Returns:
        The validated input string.

    Raises:
        VibeShieldCommandInjectionError: If null bytes or forbidden characters are found.
    """
    if '\x00' in input_str:
        raise VibeShieldCommandInjectionError("Null byte injection detected.")
    
    # Whitelist: strictly alphanumeric, hyphen, underscore, dot, @, colon. No spaces.
    whitelist = r'^[a-zA-Z0-9_\-\.@:]+$'
    if not re.match(whitelist, input_str):
        raise VibeShieldCommandInjectionError(f"Input \"{input_str}\" contains forbidden characters.")
    return input_str

def validate_safe_command(command: str, args: list[str], allowed_commands: list[str] = None) -> None:
    """
    Validates that the command and its arguments are safe for execution.

    Args:
        command: The command name/binary to validate.
        args: List of command-line arguments.
        allowed_commands: Optional custom allowed commands whitelist.

    Raises:
        VibeShieldCommandInjectionError: If validation fails.
    """
    clean_command = command.strip()
    
    # Prevent directory / path traversal in command path
    if '/' in clean_command or '\\' in clean_command or '..' in clean_command:
        raise VibeShieldCommandInjectionError(f"Path injection or traversal detected in command \"{command}\".")

    allowed_list = allowed_commands if allowed_commands is not None else DEFAULT_ALLOWED_COMMANDS
    if clean_command not in allowed_list:
        raise VibeShieldCommandInjectionError(f"Command \"{clean_command}\" is not in the allowed list.")

    # Prevent path traversal in command arguments
    for arg in args:
        if '..' in arg or '/' in arg or '\\' in arg:
            raise VibeShieldCommandInjectionError(f"Path traversal or directory separator detected in argument \"{arg}\".")
