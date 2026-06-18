"""
⚠️ WARNING: SQL ESCAPING IS PARTIAL MITIGATION ONLY

This sanitizer provides defense-in-depth but is NOT a substitute for:
- Parameterized queries (prepared statements)
- ORM query builders
- Input validation

SQL escaping (single quote doubling) can be bypassed in certain character sets
and edge cases. ALWAYS use parameterized queries for database operations.
"""

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
