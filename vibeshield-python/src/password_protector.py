import math
import re
from typing import Any, Dict, List, Optional

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "letmein", "admin",
    "welcome", "monkey", "master", "dragon", "login", "princess", "football", "shadow", "sunshine", "trustno1",
    "1234567890", "1234", "111111", "123123", "password123", "admin123", "admin1234", "qwertyuiop",
    "hello", "computer", "keyboard", "master123", "guest", "root", "oracle", "secret", "security", "charlie",
    "alexander", "superman", "batman", "spiderman", "pokemon", "starwars", "soccer", "baseball", "basketball",
    "hockey", "chelsea", "arsenal", "liverpool", "manchester", "barcelona", "realmadrid", "juventus", "milan",
    "inter", "bayern", "dortmund", "schalke", "ajax", "psg", "marseille", "lyon", "monaco", "roma",
    "napoli", "lazio", "fiorentina", "torino", "sampdoria", "genoa", "bologna", "cagliari", "parma", "verona",
    "udinese", "lecce", "brescia", "spal", "sassuolo", "atalanta", "empoli", "frosinone", "chievo", "palermo",
    "catania", "bari", "siena", "livorno", "reggina", "messina", "ascoli", "treviso", "triestina", "vicenza",
    "perugia", "venezia", "ancona", "salernitana", "foggia", "avellino", "taranto", "brindisi", "potenza", "mater",
    "benvenuto", "amigo", "hola", "bonjour", "gutentag", "ciao", "privet", "nihao", "konnichiwa", "aloha",
    "sayonara", "adios", "aurevoir", "aufwiedersehen", "arrivederci", "poka", "zajian", "namaste", "shalom",
    "123456a", "123456b", "123456c", "123456d", "123456e", "123456f", "123456g", "123456h", "123456i", "123456j",
    "123456k", "123456l", "123456m", "123456n", "123456o", "123456p", "123456q", "123456r", "123456s", "123456t",
    "123456u", "123456v", "123456w", "123456x", "123456y", "123456z", "qwerty123", "qwerty12345", "qwertyuiop123",
    "password12", "password1234", "password12345", "password123456", "password1234567", "password12345678",
    "password123456789", "password1234567890", "letmeout", "letmein123", "letmein1234", "letmein12345", "letmein123456",
    "welcome1", "welcome12", "welcome123", "welcome1234", "welcome12345", "welcome123456", "monkey123", "monkey1234",
    "dragon123", "dragon1234", "master1234", "login123", "login1234", "guest123", "guest1234", "root123",
    "root1234", "secret123", "secret1234", "security123", "security1234", "spiderman1", "superman1", "batman1"
}

def calculate_shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    length = len(password)
    frequencies = {}
    for char in password:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def validate_password(
    password: str,
    context: Optional[Dict[str, str]] = None,
    min_length: int = 12,
    max_length: int = 128,
    require_complexity: bool = True
) -> Dict[str, Any]:
    errors = []
    warnings = []

    if not password:
        return {
            "valid": False,
            "score": 0,
            "entropy": 0.0,
            "errors": ["Password cannot be empty"],
            "warnings": [],
            "strength": "very_weak"
        }

    # 1. Length checks
    if len(password) > max_length:
        errors.append(f"Password length exceeds maximum limit of {max_length} characters")
    if len(password) < min_length:
        errors.append(f"Password is too short (minimum {min_length} characters required)")

    password_lower = password.lower()

    # 2. Common Password Blacklist check
    is_common = password_lower in COMMON_PASSWORDS
    if is_common:
        errors.append("Password is one of the most commonly used passwords")

    # 3. Complexity check
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    category_count = sum([has_upper, has_lower, has_digit, has_special])
    if require_complexity and category_count < 3:
        errors.append("Password must contain characters from at least 3 complexity groups (uppercase, lowercase, digits, special characters)")

    # 4. Context Leak Validation
    if context:
        if context.get("username") and len(context["username"]) >= 3:
            if context["username"].lower() in password_lower:
                errors.append("Password contains predictable user context information: username")
        if context.get("firstName") and len(context["firstName"]) >= 3:
            if context["firstName"].lower() in password_lower:
                errors.append("Password contains predictable user context information: firstName")
        if context.get("lastName") and len(context["lastName"]) >= 3:
            if context["lastName"].lower() in password_lower:
                errors.append("Password contains predictable user context information: lastName")
        if context.get("email"):
            email_parts = re.split(r"[@.]", context["email"].lower())
            for part in email_parts:
                if len(part) >= 3 and part in password_lower:
                    errors.append("Password contains predictable user context information: email parts")
                    break
        if context.get("birthDate"):
            date_parts = re.split(r"[-/.]", context["birthDate"])
            for part in date_parts:
                if len(part) >= 2 and part in password_lower:
                    errors.append("Password contains predictable user context information: birthDate parts")
                    break

    # 5. Repetitive & Sequential pattern check
    has_repetitive = False
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            has_repetitive = True
            break
    if has_repetitive:
        warnings.append("Password contains repetitive characters")

    has_sequential = False
    for i in range(len(password) - 2):
        code1 = ord(password[i])
        code2 = ord(password[i + 1])
        code3 = ord(password[i + 2])
        if (code2 == code1 + 1 and code3 == code2 + 1) or (code2 == code1 - 1 and code3 == code2 - 1):
            has_sequential = True
            break
    if has_sequential:
        warnings.append("Password contains sequential characters")

    # Shannon Entropy
    entropy = calculate_shannon_entropy(password)

    # 6. Scoring Algorithm
    score = 0
    # Length points (max 40)
    score += min(len(password) * 4, 40)
    # Complexity points (max 40)
    score += category_count * 10
    # Entropy bonus (max 20)
    score += min(entropy * 5, 20)

    # Apply reductions
    if is_common:
        score = min(score, 10)
    if len(password) < min_length or len(password) > max_length:
        score = min(score, 5)
    if any("context" in e for e in errors):
        score = max(0, score - 30)
    if has_repetitive:
        score = max(0, score - 15)
    if has_sequential:
        score = max(0, score - 15)

    score = round(score)
    score = max(0, min(score, 100))

    # Strength classification
    if score < 20:
        strength = "very_weak"
    elif score < 40:
        strength = "weak"
    elif score < 60:
        strength = "medium"
    elif score < 80:
        strength = "strong"
    else:
        strength = "very_strong"

    return {
        "valid": len(errors) == 0,
        "score": score,
        "entropy": entropy,
        "errors": errors,
        "warnings": warnings,
        "strength": strength
    }

def generate_password_policy_report(password: str, context: Optional[Dict[str, str]] = None) -> str:
    result = validate_password(password, context)
    status = "✅ SECURE" if result["valid"] else "❌ WEAK"
    errors_str = "\n".join(f"  - {e}" for e in result["errors"]) if result["errors"] else "  - None"
    warnings_str = "\n".join(f"  - {w}" for w in result["warnings"]) if result["warnings"] else "  - None"
    
    return f"""Password Assessment Report: {status}
----------------------------------------
Strength Score: {result['score']}/100 ({result['strength'].upper().replace('_', ' ')})
Shannon Entropy: {result['entropy']} bits
Validation Status: {'Pass' if result['valid'] else 'Fail'}
Errors:
{errors_str}
Warnings:
{warnings_str}
----------------------------------------"""
