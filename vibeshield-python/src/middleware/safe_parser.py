from ..deserialization_protector import safe_json_parse

def enforce_safe_json(body_text: str, max_depth: int = 64) -> dict:
    """
    Enforces safe JSON parsing of request bodies, validating depth.

    Args:
        body_text: The raw request body text.
        max_depth: The maximum nesting depth allowed.

    Returns:
        The deserialized and sanitized JSON dictionary, or an empty dictionary if input is empty.

    Raises:
        VibeShieldDeserializationError: If JSON validation fails or depth limit is exceeded.
    """
    if not body_text or body_text.strip() == '':
        return {}
    return safe_json_parse(body_text, max_depth)
