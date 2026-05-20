import re

def sanitize(val):
    """
    Recursively sanitizes input values to prevent XSS, SQLi, and NoSQLi attacks.
    """
    if isinstance(val, str):
        # 1. Remove script tags and their content (case-insensitive)
        cleaned = re.sub(r'<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>', '', val, flags=re.IGNORECASE)
        # 2. Strip remaining HTML tags
        cleaned = re.sub(r'<[^>]*>', '', cleaned)
        # 3. Neutralize javascript: protocol
        cleaned = re.sub(r'javascript:', 'unsafe-protocol:', cleaned, flags=re.IGNORECASE)
        # 4. Escape SQL injection characters
        cleaned = cleaned.replace("'", "''")
        cleaned = cleaned.replace('--', ' - - ')
        cleaned = cleaned.replace('/*', ' / * ')
        cleaned = cleaned.replace('*/', ' * / ')
        return cleaned
    elif isinstance(val, dict):
        return {
            k: sanitize(v) 
            for k, v in val.items() 
            if not (isinstance(k, str) and k.startswith('$'))
        }
    elif isinstance(val, list):
        return [sanitize(item) for item in val]
    return val
