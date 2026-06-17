"""
VibeShield SSRF URL Validator

Provides protection against Server-Side Request Forgery (SSRF) vulnerabilities by
validating target URLs, detecting homograph attacks, and resolving obfuscated IP addresses.
"""

import urllib.parse
import ipaddress
import re
import logging
from typing import Any, Dict, Optional, List

# Setup logger following codebase conventions
logger = logging.getLogger("VibeShield")

# RegEx patterns compiled as constants (UPPER_SNAKE_CASE)
LATIN_PATTERN = re.compile(r'[a-zA-Z]')
CYRILLIC_PATTERN = re.compile(r'[\u0400-\u04FF]')
GREEK_PATTERN = re.compile(r'[\u0370-\u03FF]')
HEX_OCT_DEC_PATTERN = re.compile(r'^[0-9a-fA-FxX.]*$')
OCTAL_PATTERN = re.compile(r'^[0-7]+$')
DIGIT_PATTERN = re.compile(r'^\d+$')


def parse_ipv4(hostname: str) -> Optional[List[int]]:
    """
    Decodes hex, octal, decimal IP addresses (including carry-over / fewer than 4 parts).

    Args:
        hostname: The hostname or IP-like string to decode and parse.

    Returns:
        A list of 4 integers representing the IPv4 octets, or None if invalid or not IP-like.
    """
    clean = hostname.strip()
    if not HEX_OCT_DEC_PATTERN.match(clean):
        return None
    parts = clean.split('.')
    if len(parts) == 0 or len(parts) > 4:
        return None
    parsed_values = []
    for part in parts:
        if part == '':
            return None
        try:
            if part.lower().startswith('0x'):
                val = int(part, 16)
            elif part.startswith('0') and len(part) > 1:
                if not OCTAL_PATTERN.match(part):
                    return None
                val = int(part, 8)
            else:
                if not DIGIT_PATTERN.match(part):
                    return None
                val = int(part, 10)
        except ValueError:
            return None
        if val < 0:
            return None
        parsed_values.append(val)

    ipv4_val = 0
    length = len(parsed_values)
    if length == 1:
        ipv4_val = parsed_values[0]
    elif length == 2:
        if parsed_values[0] > 255 or parsed_values[1] > 16777215:
            return None
        ipv4_val = (parsed_values[0] << 24) + parsed_values[1]
    elif length == 3:
        if parsed_values[0] > 255 or parsed_values[1] > 255 or parsed_values[2] > 65535:
            return None
        ipv4_val = (parsed_values[0] << 24) + (parsed_values[1] << 16) + parsed_values[2]
    elif length == 4:
        if parsed_values[0] > 255 or parsed_values[1] > 255 or parsed_values[2] > 255 or parsed_values[3] > 255:
            return None
        ipv4_val = (parsed_values[0] << 24) + (parsed_values[1] << 16) + (parsed_values[2] << 8) + parsed_values[3]

    if ipv4_val < 0 or ipv4_val > 4294967295:
        return None

    o1 = (ipv4_val // 16777216) & 0xff
    o2 = (ipv4_val // 65536) & 0xff
    o3 = (ipv4_val // 256) & 0xff
    o4 = ipv4_val & 0xff
    return [o1, o2, o3, o4]


def validate_url(target_url: str) -> Dict[str, Any]:
    """
    Validates a URL to prevent SSRF vulnerabilities.

    Args:
        target_url: The URL string to validate.

    Returns:
        Dictionary with keys 'safe' (bool) and 'reason' (str, optional).
    """
    try:
        parsed = urllib.parse.urlparse(target_url)
        scheme = parsed.scheme.lower()
        if scheme not in ('http', 'https'):
            return {'safe': False, 'reason': f"Forbidden protocol: {parsed.scheme}"}
        
        hostname = parsed.hostname
        if not hostname:
            return {'safe': False, 'reason': "Missing or invalid hostname"}
        
        hostname = hostname.lower()

        # Homograph check (script mixing detection)
        has_latin = bool(LATIN_PATTERN.search(hostname))
        has_cyrillic = bool(CYRILLIC_PATTERN.search(hostname))
        has_greek = bool(GREEK_PATTERN.search(hostname))
        if (has_latin and has_cyrillic) or (has_latin and has_greek) or (has_cyrillic and has_greek):
            return {'safe': False, 'reason': "Potential IDN homograph attack detected"}

        if hostname.startswith('[') and hostname.endswith(']'):
            hostname = hostname[1:-1]

        if hostname in ('localhost', '0.0.0.0', '::1', '::', '::ffff:0.0.0.0'):
            return {'safe': False, 'reason': f"Blocked loopback/unspecified hostname: {hostname}"}

        # Check if decoded IPv4
        ipv4 = parse_ipv4(hostname)
        if ipv4:
            ip_str = ".".join(map(str, ipv4))
            ip = ipaddress.ip_address(ip_str)
        else:
            try:
                ip = ipaddress.ip_address(hostname)
            except ValueError:
                # Treat as a normal domain
                return {'safe': True}

        # Check subnet ranges
        if ip.is_loopback:
            return {'safe': False, 'reason': f"Loopback IP address blocked: {ip}"}
        if ip.is_private:
            return {'safe': False, 'reason': f"Private IP address blocked: {ip}"}
        if ip.is_link_local:
            return {'safe': False, 'reason': f"Link-local IP address blocked: {ip}"}
        if ip.is_reserved:
            return {'safe': False, 'reason': f"Reserved IP address blocked: {ip}"}
        if ip.is_multicast:
            return {'safe': False, 'reason': f"Multicast IP address blocked: {ip}"}

        # Check Carrier-grade NAT manually for IPv4 if not covered by standard checks
        if ip.version == 4:
            # 100.64.0.0/10 -> 100.64.0.0 to 100.127.255.255
            o1, o2, _, _ = map(int, str(ip).split('.'))
            if o1 == 100 and o2 >= 64 and o2 <= 127:
                return {'safe': False, 'reason': f"Carrier-grade NAT IP address blocked: {ip}"}

        return {'safe': True}

    except Exception as e:
        return {'safe': False, 'reason': f"Invalid URL format: {str(e)}"}
