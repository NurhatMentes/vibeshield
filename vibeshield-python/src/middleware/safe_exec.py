import subprocess
import logging
from ..command_sanitizer import sanitize_shell_input, validate_safe_command

logger = logging.getLogger("VibeShield")

def safe_exec(command: str, args: list[str], options: dict = None, allowed_commands: list[str] = None) -> dict:
    """
    Safely executes a shell command with shell=False.

    Args:
        command: The command name to execute.
        args: List of argument strings.
        options: Dict of subprocess.run options.
        allowed_commands: Optional custom allowed commands whitelist.

    Returns:
        Dict with keys:
            - stdout (str)
            - stderr (str)
            - code (int)
    """
    validate_safe_command(command, args, allowed_commands)
    sanitized_args = [sanitize_shell_input(arg) for arg in args]
    
    opts = options.copy() if options else {}
    # Force shell=False and capture output
    opts['shell'] = False
    opts['capture_output'] = True
    opts['text'] = True
    
    try:
        run_args = [command] + sanitized_args
        result = subprocess.run(run_args, **opts)
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'code': result.returncode
        }
    except Exception as e:
        logger.error("[VibeShield] Command execution failed: %s", str(e))
        raise
