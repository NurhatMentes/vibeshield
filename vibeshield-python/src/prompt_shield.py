import re
import secrets
from typing import Dict, List, Optional, Any

DIRECT_INJECTION_PATTERNS = [
    {
        'pattern': re.compile(
            r'ignore\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|directives|prompts|code)',
            re.IGNORECASE
        ),
        'score': 80,
        'label': 'Ignore previous instructions'
    },
    {
        'pattern': re.compile(
            r'disregard\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|directives|programming|code)',
            re.IGNORECASE
        ),
        'score': 80,
        'label': 'Disregard instructions'
    },
    {
        'pattern': re.compile(
            r'forget\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|context|prompts|code)',
            re.IGNORECASE
        ),
        'score': 80,
        'label': 'Forget instructions'
    },
    {
        'pattern': re.compile(
            r'override\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|settings|restrictions|code)',
            re.IGNORECASE
        ),
        'score': 90,
        'label': 'Override instructions'
    },
    {
        'pattern': re.compile(r'new\s+instructions?\s*[:=]', re.IGNORECASE),
        'score': 70,
        'label': 'New instructions declaration'
    },
    {
        'pattern': re.compile(r'you\s+must\s+now\s+(follow|obey|listen)', re.IGNORECASE),
        'score': 75,
        'label': 'Coercive directive'
    },
    {
        'pattern': re.compile(r'from\s+now\s+on[,.]?\s+(you|ignore|do|act|behave|respond)', re.IGNORECASE),
        'score': 70,
        'label': 'Behavioral override'
    },
    {
        'pattern': re.compile(r'stop\s+(being|acting\s+as)\s+a(n)?\s+(ai|assistant|bot|chatbot)', re.IGNORECASE),
        'score': 75,
        'label': 'Stop being AI'
    },
    {
        'pattern': re.compile(r'do\s+not\s+(follow|obey|listen\s+to)\s+(your|the|any)\s+(instructions|rules|guidelines|programming)', re.IGNORECASE),
        'score': 85,
        'label': 'Do not follow rules'
    },
    {
        'pattern': re.compile(r'system\s*prompt\s*[:=]\s*', re.IGNORECASE),
        'score': 90,
        'label': 'System prompt override'
    },
    {
        'pattern': re.compile(r'\[\s*system\s*\]', re.IGNORECASE),
        'score': 85,
        'label': 'System tag injection'
    },
    {
        'pattern': re.compile(r'<<\s*sys\s*>>', re.IGNORECASE),
        'score': 85,
        'label': 'Sys tag injection'
    },
    {
        'pattern': re.compile(r'\|\s*system\s*\|', re.IGNORECASE),
        'score': 80,
        'label': 'Pipe system tag'
    },
    {
        'pattern': re.compile(r'delete\s+(all\s+)?instructions', re.IGNORECASE),
        'score': 80,
        'label': 'Delete instructions'
    },
    {
        'pattern': re.compile(r'clear\s+(all\s+)?instructions', re.IGNORECASE),
        'score': 80,
        'label': 'Clear instructions'
    },
]

JAILBREAK_PATTERNS = [
    {
        'pattern': re.compile(r'\bDAN\b.*\b(mode|prompt|enabled|activated)', re.IGNORECASE),
        'score': 100,
        'label': 'DAN mode activation'
    },
    {
        'pattern': re.compile(r'\bdo\s+anything\s+now\b', re.IGNORECASE),
        'score': 100,
        'label': 'Do Anything Now'
    },
    {
        'pattern': re.compile(r'\bdeveloper\s+mode\s*(enabled|activated|on)?\b', re.IGNORECASE),
        'score': 95,
        'label': 'Developer mode'
    },
    {
        'pattern': re.compile(r'\bjailbreak(ed|ing)?\b', re.IGNORECASE),
        'score': 90,
        'label': 'Jailbreak keyword'
    },
    {
        'pattern': re.compile(r'\bunrestricted\s+mode\b', re.IGNORECASE),
        'score': 90,
        'label': 'Unrestricted mode'
    },
    {
        'pattern': re.compile(r'\bgod\s+mode\b', re.IGNORECASE),
        'score': 90,
        'label': 'God mode'
    },
    {
        'pattern': re.compile(r'\bsuper\s*user\s+mode\b', re.IGNORECASE),
        'score': 85,
        'label': 'Superuser mode'
    },
    {
        'pattern': re.compile(r'\bno\s+(restrictions?|limitations?|boundaries|filters?|rules?)\b', re.IGNORECASE),
        'score': 80,
        'label': 'No restrictions'
    },
    {
        'pattern': re.compile(r'\bbypass\s+(safety|content|ethical|security)\s*(filter|check|restriction|guard)', re.IGNORECASE),
        'score': 95,
        'label': 'Bypass safety'
    },
    {
        'pattern': re.compile(r'\banti[- ]?censorship\b', re.IGNORECASE),
        'score': 80,
        'label': 'Anti-censorship'
    },
    {
        'pattern': re.compile(r'\buncensored\s+(mode|version|model)\b', re.IGNORECASE),
        'score': 85,
        'label': 'Uncensored mode'
    },
    {
        'pattern': re.compile(r'\benable\s+(evil|malicious|hack|unsafe)\s+mode\b', re.IGNORECASE),
        'score': 95,
        'label': 'Evil mode'
    },
    {
        'pattern': re.compile(r'\bjailbreak\s+prompt\b', re.IGNORECASE),
        'score': 90,
        'label': 'Jailbreak prompt keyword'
    },
]

PROMPT_LEAK_PATTERNS = [
    {
        'pattern': re.compile(r'show\s+(me\s+)?(your|the)\s+(system\s+)?prompt', re.IGNORECASE),
        'score': 75,
        'label': 'Show prompt'
    },
    {
        'pattern': re.compile(r'reveal\s+(your|the)\s+(instructions|system\s+prompt|rules|guidelines)', re.IGNORECASE),
        'score': 80,
        'label': 'Reveal instructions'
    },
    {
        'pattern': re.compile(r'what\s+(are|is)\s+(your|the)\s+(system\s+)?(instructions|prompt|rules|guidelines|directives)', re.IGNORECASE),
        'score': 70,
        'label': 'What are your instructions'
    },
    {
        'pattern': re.compile(r'repeat\s+(your|the)\s+(system\s+)?(instructions|prompt|rules)', re.IGNORECASE),
        'score': 80,
        'label': 'Repeat instructions'
    },
    {
        'pattern': re.compile(r'print\s+(your|the)\s+(system\s+)?(prompt|instructions|initial\s+prompt)', re.IGNORECASE),
        'score': 80,
        'label': 'Print prompt'
    },
    {
        'pattern': re.compile(r'output\s+(your|the)\s+(system\s+)?(prompt|instructions|initialization)', re.IGNORECASE),
        'score': 80,
        'label': 'Output prompt'
    },
    {
        'pattern': re.compile(r'display\s+(your|the)\s+(hidden|system|secret)\s+(prompt|instructions)', re.IGNORECASE),
        'score': 85,
        'label': 'Display hidden prompt'
    },
    {
        'pattern': re.compile(r'dump\s+(your|the)\s+(system|initial|original)\s*(prompt|instructions|context)', re.IGNORECASE),
        'score': 85,
        'label': 'Dump prompt'
    },
    {
        'pattern': re.compile(r'tell\s+me\s+(your|the)\s+(exact|full|complete|entire)\s+(instructions|prompt|system\s+prompt)', re.IGNORECASE),
        'score': 80,
        'label': 'Tell me exact instructions'
    },
    {
        'pattern': re.compile(r'how\s+were\s+you\s+(initialized|programmed|created)', re.IGNORECASE),
        'score': 65,
        'label': 'Creation inquiry'
    },
]

VIRTUALIZATION_PATTERNS = [
    {
        'pattern': re.compile(r'imagine\s+you\s+are\s+(a|an|the|not)', re.IGNORECASE),
        'score': 60,
        'label': 'Imagine you are'
    },
    {
        'pattern': re.compile(r'pretend\s+(to\s+be|you\s+are|that\s+you)', re.IGNORECASE),
        'score': 65,
        'label': 'Pretend to be'
    },
    {
        'pattern': re.compile(r'roleplay\s+(as|that|where)\b', re.IGNORECASE),
        'score': 55,
        'label': 'Roleplay as'
    },
    {
        'pattern': re.compile(r'act\s+as\s+(if|though|a|an)\s', re.IGNORECASE),
        'score': 55,
        'label': 'Act as'
    },
    {
        'pattern': re.compile(r'you\s+are\s+now\s+(a|an|the|no\s+longer)', re.IGNORECASE),
        'score': 70,
        'label': 'You are now'
    },
    {
        'pattern': re.compile(r'simulate\s+(being|a|an|the)\b', re.IGNORECASE),
        'score': 55,
        'label': 'Simulate being'
    },
    {
        'pattern': re.compile(r'switch\s+to\s+(a\s+)?different\s+(persona|character|mode|personality)', re.IGNORECASE),
        'score': 65,
        'label': 'Switch persona'
    },
    {
        'pattern': re.compile(r'enter\s+(character|persona|role)\s+(mode|as)', re.IGNORECASE),
        'score': 60,
        'label': 'Enter character mode'
    },
]

INDIRECT_INJECTION_PATTERNS = [
    {
        'pattern': re.compile(r'when\s+(the|an?)\s+(ai|assistant|model|bot|llm)\s+(reads?|sees?|processes?|encounters?)', re.IGNORECASE),
        'score': 70,
        'label': 'When AI reads'
    },
    {
        'pattern': re.compile(r'hidden\s+instruction', re.IGNORECASE),
        'score': 75,
        'label': 'Hidden instruction'
    },
    {
        'pattern': re.compile(r'invisible\s+(text|instruction|command|prompt)', re.IGNORECASE),
        'score': 75,
        'label': 'Invisible instruction'
    },
    {
        'pattern': re.compile(r'execute\s+(this|the\s+following)\s+(command|instruction|code)', re.IGNORECASE),
        'score': 80,
        'label': 'Execute command'
    },
    {
        'pattern': re.compile(r'\[INST\]', re.IGNORECASE),
        'score': 85,
        'label': 'INST tag injection'
    },
    {
        'pattern': re.compile(r'<\|im_start\|>', re.IGNORECASE),
        'score': 90,
        'label': 'ChatML injection'
    },
    {
        'pattern': re.compile(r'<\|im_end\|>', re.IGNORECASE),
        'score': 90,
        'label': 'ChatML end injection'
    },
    {
        'pattern': re.compile(r'###\s*(Human|System|Assistant|User)\s*:', re.IGNORECASE),
        'score': 85,
        'label': 'Role delimiter injection'
    },
]

FALSE_POSITIVE_EXCLUDE = re.compile(
    r'\b(how|why|error|code|python|typescript|javascript|git|compile)\b',
    re.IGNORECASE
)
FALSE_POSITIVE_CONNECTIVE = re.compile(
    r'\b(in|to|with)\b',
    re.IGNORECASE
)


def generate_canary_token() -> str:
    random_hex = secrets.token_hex(16)
    return f"CANARY_VIBESHIELD_{random_hex}"


def detect_prompt_injection(
    input_text: str,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if not input_text:
        return {
            'safe': True,
            'score': 0,
            'risk_level': 'none',
            'threats': [],
            'summary': 'Input is empty'
        }

    options = options or {}
    threshold_medium = options.get('threshold_medium', 50)
    threshold_high = options.get('threshold_high', 100)
    threshold_critical = options.get('threshold_critical', 150)

    threats = []
    total_score = 0

    scan_list = [
        (DIRECT_INJECTION_PATTERNS, 'direct_injection'),
        (JAILBREAK_PATTERNS, 'jailbreak'),
        (PROMPT_LEAK_PATTERNS, 'prompt_leak'),
        (VIRTUALIZATION_PATTERNS, 'virtualization'),
        (INDIRECT_INJECTION_PATTERNS, 'indirect_injection'),
    ]

    for rule_list, threat_type in scan_list:
        for rule in rule_list:
            if rule['pattern'].search(input_text):
                # False positive check matching TypeScript side
                if (threat_type == 'direct_injection' and
                        rule['label'] == 'Ignore previous instructions' and
                        FALSE_POSITIVE_EXCLUDE.search(input_text) and
                        FALSE_POSITIVE_CONNECTIVE.search(input_text)):
                    continue

                threats.append({
                    'type': threat_type,
                    'pattern': rule['label'],
                    'score': rule['score']
                })
                total_score += rule['score']

    custom_patterns = options.get('custom_patterns', [])
    for rule in custom_patterns:
        pattern = rule.get('pattern')
        if pattern and pattern.search(input_text):
            threats.append({
                'type': rule.get('type', 'custom'),
                'pattern': str(pattern),
                'score': rule.get('score', 50)
            })
            total_score += rule.get('score', 50)

    risk_level = 'none'
    if total_score >= threshold_critical:
        risk_level = 'critical'
    elif total_score >= threshold_high:
        risk_level = 'high'
    elif total_score >= threshold_medium:
        risk_level = 'medium'
    elif total_score > 0:
        risk_level = 'low'

    safe = total_score == 0

    summary = (
        "Input is safe" if safe
        else f"Detected {len(threats)} threat(s) with total score {total_score}. Risk level: {risk_level}."
    )

    return {
        'safe': safe,
        'score': total_score,
        'risk_level': risk_level,
        'threats': threats,
        'summary': summary
    }


def detect_jailbreak(input_text: str) -> Dict[str, Any]:
    if not input_text:
        return {'detected': False, 'score': 0, 'patterns': []}

    total_score = 0
    matched_patterns = []

    for rule in JAILBREAK_PATTERNS:
        if rule['pattern'].search(input_text):
            total_score += rule['score']
            matched_patterns.append(rule['label'])

    detected = total_score >= 70

    return {
        'detected': detected,
        'score': total_score,
        'patterns': matched_patterns
    }


def detect_prompt_leak(
    output: str,
    canary_tokens: Optional[List[str]] = None
) -> Dict[str, Any]:
    if not output:
        return {'leaked': False, 'matches': []}

    matches = []

    if canary_tokens:
        for token in canary_tokens:
            if token in output:
                matches.append(f"CanaryToken: {token}")

    leak_indicators = [
        re.compile(r'my\s+instructions\b', re.IGNORECASE),
        re.compile(r'system\s+prompt\s*:', re.IGNORECASE),
        re.compile(r'here\s+are\s+your\s+instructions', re.IGNORECASE),
        re.compile(r'you\s+are\s+a\s+helpful\s+assistant\s+programmed\s+to', re.IGNORECASE),
        re.compile(r'initial\s+system\s+instructions', re.IGNORECASE),
    ]

    for regex in leak_indicators:
        if regex.search(output):
            matches.append(f"Indicator match: {regex.pattern}")

    return {
        'leaked': len(matches) > 0,
        'matches': matches
    }


def sanitize_for_llm(input_text: str) -> str:
    if not input_text:
        return ""

    sanitized = input_text

    replacements = [
        (re.compile(r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|directives|prompts)', re.IGNORECASE), '[neutralized ignore instruction]'),
        (re.compile(r'disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|directives|programming)', re.IGNORECASE), '[neutralized disregard instruction]'),
        (re.compile(r'forget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|context|prompts)', re.IGNORECASE), '[neutralized forget instruction]'),
        (re.compile(r'override\s+(all\s+)?(previous|prior|above|earlier|your|system)\s+(instructions|rules|guidelines|settings|restrictions)', re.IGNORECASE), '[neutralized override instruction]'),
        (re.compile(r'system\s*prompt\s*[:=]\s*', re.IGNORECASE), 'system prompt override attempt: '),
        (re.compile(r'<\|im_start\|>', re.IGNORECASE), '[im_start]'),
        (re.compile(r'<\|im_end\|>', re.IGNORECASE), '[im_end]'),
        (re.compile(r'\[INST\]', re.IGNORECASE), '[inst]'),
    ]

    for regex, replacement in replacements:
        sanitized = regex.sub(replacement, sanitized)

    return f"--- USER INPUT START ---\n{sanitized}\n--- USER INPUT END ---"
