import * as crypto from 'crypto';

export interface PromptShieldResult {
  safe: boolean;
  score: number;
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  threats: Array<{ type: string; pattern: string; score: number }>;
  summary: string;
}

export interface PromptShieldOptions {
  thresholdMedium?: number;   // default 50
  thresholdHigh?: number;     // default 100
  thresholdCritical?: number; // default 150
  enableSanitization?: boolean;
  customPatterns?: Array<{ pattern: RegExp; type: string; score: number }>;
}

export interface CanaryToken {
  token: string;
  createdAt: number;
}

export const DIRECT_INJECTION_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|directives|prompts|code)/i, score: 80, label: 'Ignore previous instructions' },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|directives|programming|code)/i, score: 80, label: 'Disregard instructions' },
  { pattern: /forget\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|context|prompts|code)/i, score: 80, label: 'Forget instructions' },
  { pattern: /override\s+(all\s+)?(previous|prior|above|earlier|your|system|any)?\s*(prior|previous|initial)?\s*(instructions|rules|guidelines|settings|restrictions|code)/i, score: 90, label: 'Override instructions' },
  { pattern: /new\s+instructions?\s*[:=]/i, score: 70, label: 'New instructions declaration' },
  { pattern: /you\s+must\s+now\s+(follow|obey|listen)/i, score: 75, label: 'Coercive directive' },
  { pattern: /from\s+now\s+on[,.]?\s+(you|ignore|do|act|behave|respond)/i, score: 70, label: 'Behavioral override' },
  { pattern: /stop\s+(being|acting\s+as)\s+a(n)?\s+(ai|assistant|bot|chatbot)/i, score: 75, label: 'Stop being AI' },
  { pattern: /do\s+not\s+(follow|obey|listen\s+to)\s+(your|the|any)\s+(instructions|rules|guidelines|programming)/i, score: 85, label: 'Do not follow rules' },
  { pattern: /system\s*prompt\s*[:=]\s*/i, score: 90, label: 'System prompt override' },
  { pattern: /\[\s*system\s*\]/i, score: 85, label: 'System tag injection' },
  { pattern: /<<\s*sys\s*>>/i, score: 85, label: 'Sys tag injection' },
  { pattern: /\|\s*system\s*\|/i, score: 80, label: 'Pipe system tag' },
  { pattern: /delete\s+(all\s+)?instructions/i, score: 80, label: 'Delete instructions' },
  { pattern: /clear\s+(all\s+)?instructions/i, score: 80, label: 'Clear instructions' },
];

export const JAILBREAK_PATTERNS = [
  { pattern: /\bDAN\b.*\b(mode|prompt|enabled|activated)/i, score: 100, label: 'DAN mode activation' },
  { pattern: /\bdo\s+anything\s+now\b/i, score: 100, label: 'Do Anything Now' },
  { pattern: /\bdeveloper\s+mode\s*(enabled|activated|on)?\b/i, score: 95, label: 'Developer mode' },
  { pattern: /\bjailbreak(ed|ing)?\b/i, score: 90, label: 'Jailbreak keyword' },
  { pattern: /\bunrestricted\s+mode\b/i, score: 90, label: 'Unrestricted mode' },
  { pattern: /\bgod\s+mode\b/i, score: 90, label: 'God mode' },
  { pattern: /\bsuper\s*user\s+mode\b/i, score: 85, label: 'Superuser mode' },
  { pattern: /\bno\s+(restrictions?|limitations?|boundaries|filters?|rules?)\b/i, score: 80, label: 'No restrictions' },
  { pattern: /\bbypass\s+(safety|content|ethical|security)\s*(filter|check|restriction|guard)/i, score: 95, label: 'Bypass safety' },
  { pattern: /\banti[- ]?censorship\b/i, score: 80, label: 'Anti-censorship' },
  { pattern: /\buncensored\s+(mode|version|model)\b/i, score: 85, label: 'Uncensored mode' },
  { pattern: /\benable\s+(evil|malicious|hack|unsafe)\s+mode\b/i, score: 95, label: 'Evil mode' },
  { pattern: /\bjailbreak\s+prompt\b/i, score: 90, label: 'Jailbreak prompt keyword' },
];

export const PROMPT_LEAK_PATTERNS = [
  { pattern: /show\s+(me\s+)?(your|the)\s+(system\s+)?prompt/i, score: 75, label: 'Show prompt' },
  { pattern: /reveal\s+(your|the)\s+(instructions|system\s+prompt|rules|guidelines)/i, score: 80, label: 'Reveal instructions' },
  { pattern: /what\s+(are|is)\s+(your|the)\s+(system\s+)?(instructions|prompt|rules|guidelines|directives)/i, score: 70, label: 'What are your instructions' },
  { pattern: /repeat\s+(your|the)\s+(system\s+)?(instructions|prompt|rules)/i, score: 80, label: 'Repeat instructions' },
  { pattern: /print\s+(your|the)\s+(system\s+)?(prompt|instructions|initial\s+prompt)/i, score: 80, label: 'Print prompt' },
  { pattern: /output\s+(your|the)\s+(system\s+)?(prompt|instructions|initialization)/i, score: 80, label: 'Output prompt' },
  { pattern: /display\s+(your|the)\s+(hidden|system|secret)\s+(prompt|instructions)/i, score: 85, label: 'Display hidden prompt' },
  { pattern: /dump\s+(your|the)\s+(system|initial|original)\s*(prompt|instructions|context)/i, score: 85, label: 'Dump prompt' },
  { pattern: /tell\s+me\s+(your|the)\s+(exact|full|complete|entire)\s+(instructions|prompt|system\s+prompt)/i, score: 80, label: 'Tell me exact instructions' },
  { pattern: /how\s+were\s+you\s+(initialized|programmed|created)/i, score: 65, label: 'Creation inquiry' },
];


export const VIRTUALIZATION_PATTERNS = [
  { pattern: /imagine\s+you\s+are\s+(a|an|the|not)/i, score: 60, label: 'Imagine you are' },
  { pattern: /pretend\s+(to\s+be|you\s+are|that\s+you)/i, score: 65, label: 'Pretend to be' },
  { pattern: /roleplay\s+(as|that|where)\b/i, score: 55, label: 'Roleplay as' },
  { pattern: /act\s+as\s+(if|though|a|an)\s/i, score: 55, label: 'Act as' },
  { pattern: /you\s+are\s+now\s+(a|an|the|no\s+longer)/i, score: 70, label: 'You are now' },
  { pattern: /simulate\s+(being|a|an|the)\b/i, score: 55, label: 'Simulate being' },
  { pattern: /switch\s+to\s+(a\s+)?different\s+(persona|character|mode|personality)/i, score: 65, label: 'Switch persona' },
  { pattern: /enter\s+(character|persona|role)\s+(mode|as)/i, score: 60, label: 'Enter character mode' },
];

export const INDIRECT_INJECTION_PATTERNS = [
  { pattern: /when\s+(the|an?)\s+(ai|assistant|model|bot|llm)\s+(reads?|sees?|processes?|encounters?)/i, score: 70, label: 'When AI reads' },
  { pattern: /hidden\s+instruction/i, score: 75, label: 'Hidden instruction' },
  { pattern: /invisible\s+(text|instruction|command|prompt)/i, score: 75, label: 'Invisible instruction' },
  { pattern: /execute\s+(this|the\s+following)\s+(command|instruction|code)/i, score: 80, label: 'Execute command' },
  { pattern: /\[INST\]/i, score: 85, label: 'INST tag injection' },
  { pattern: /<\|im_start\|>/i, score: 90, label: 'ChatML injection' },
  { pattern: /<\|im_end\|>/i, score: 90, label: 'ChatML end injection' },
  { pattern: /###\s*(Human|System|Assistant|User)\s*:/i, score: 85, label: 'Role delimiter injection' },
];

export function generateCanaryToken(): string {
  const randomHex = crypto.randomBytes(16).toString('hex');
  return `CANARY_VIBESHIELD_${randomHex}`;
}

export function detectPromptInjection(
  input: string,
  options?: PromptShieldOptions
): PromptShieldResult {
  if (!input) {
    return {
      safe: true,
      score: 0,
      riskLevel: 'none',
      threats: [],
      summary: 'Input is empty',
    };
  }

  const thresholdMedium = options?.thresholdMedium ?? 50;
  const thresholdHigh = options?.thresholdHigh ?? 100;
  const thresholdCritical = options?.thresholdCritical ?? 150;

  const threats: Array<{ type: string; pattern: string; score: number }> = [];
  let totalScore = 0;

  const scanList = [
    { list: DIRECT_INJECTION_PATTERNS, type: 'direct_injection' },
    { list: JAILBREAK_PATTERNS, type: 'jailbreak' },
    { list: PROMPT_LEAK_PATTERNS, type: 'prompt_leak' },
    { list: VIRTUALIZATION_PATTERNS, type: 'virtualization' },
    { list: INDIRECT_INJECTION_PATTERNS, type: 'indirect_injection' },
  ];

  for (const item of scanList) {
    for (const rule of item.list) {
      if (rule.pattern.test(input)) {
        // Exclude false positives for benign lookups
        if (
          item.type === 'direct_injection' &&
          rule.label === 'Ignore previous instructions' &&
          /\b(how|why|error|code|python|typescript|javascript|git|compile)\b/i.test(input) &&
          /\b(in|to|with)\b/i.test(input)
        ) {
          continue;
        }

        threats.push({
          type: item.type,
          pattern: rule.label,
          score: rule.score,
        });
        totalScore += rule.score;
      }
    }
  }

  if (options?.customPatterns) {
    for (const rule of options.customPatterns) {
      if (rule.pattern.test(input)) {
        threats.push({
          type: rule.type,
          pattern: rule.pattern.toString(),
          score: rule.score,
        });
        totalScore += rule.score;
      }
    }
  }

  let riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical' = 'none';
  if (totalScore >= thresholdCritical) {
    riskLevel = 'critical';
  } else if (totalScore >= thresholdHigh) {
    riskLevel = 'high';
  } else if (totalScore >= thresholdMedium) {
    riskLevel = 'medium';
  } else if (totalScore > 0) {
    riskLevel = 'low';
  }

  const safe = totalScore === 0;

  const summary = safe
    ? 'Input is safe'
    : `Detected ${threats.length} threat(s) with total score ${totalScore}. Risk level: ${riskLevel}.`;

  return {
    safe,
    score: totalScore,
    riskLevel,
    threats,
    summary,
  };
}

export function detectJailbreak(
  input: string
): { detected: boolean; score: number; patterns: string[] } {
  if (!input) {
    return { detected: false, score: 0, patterns: [] };
  }

  let totalScore = 0;
  const matchedPatterns: string[] = [];

  for (const rule of JAILBREAK_PATTERNS) {
    if (rule.pattern.test(input)) {
      totalScore += rule.score;
      matchedPatterns.push(rule.label);
    }
  }

  // A lower threshold for jailbreaks specifically
  const detected = totalScore >= 70;

  return {
    detected,
    score: totalScore,
    patterns: matchedPatterns,
  };
}

export function detectPromptLeak(
  output: string,
  canaryTokens?: string[]
): { leaked: boolean; matches: string[] } {
  if (!output) {
    return { leaked: false, matches: [] };
  }

  const matches: string[] = [];

  if (canaryTokens) {
    for (const token of canaryTokens) {
      if (output.includes(token)) {
        matches.push(`CanaryToken: ${token}`);
      }
    }
  }

  // Look for common phrases indicative of prompt leaking in LLM responses
  const leakIndicators = [
    /my\s+instructions\b/i,
    /system\s+prompt\s*:/i,
    /here\s+are\s+your\s+instructions/i,
    /you\s+are\s+a\s+helpful\s+assistant\s+programmed\s+to/i,
    /initial\s+system\s+instructions/i,
  ];

  for (const regex of leakIndicators) {
    if (regex.test(output)) {
      matches.push(`Indicator match: ${regex.toString()}`);
    }
  }

  return {
    leaked: matches.length > 0,
    matches,
  };
}

export function sanitizeForLLM(input: string): string {
  if (!input) return '';

  // Neutralize common injection phrases
  let sanitized = input;

  // Replacement dictionary for neutralization
  const replacements = [
    { target: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|directives|prompts)/gi, replacement: '[neutralized ignore instruction]' },
    { target: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|directives|programming)/gi, replacement: '[neutralized disregard instruction]' },
    { target: /forget\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines|context|prompts)/gi, replacement: '[neutralized forget instruction]' },
    { target: /override\s+(all\s+)?(previous|prior|above|earlier|your|system)\s+(instructions|rules|guidelines|settings|restrictions)/gi, replacement: '[neutralized override instruction]' },
    { target: /system\s*prompt\s*[:=]\s*/gi, replacement: 'system prompt override attempt: ' },
    { target: /<\|im_start\|>/g, replacement: '[im_start]' },
    { target: /<\|im_end\|>/g, replacement: '[im_end]' },
    { target: /\[INST\]/g, replacement: '[inst]' },
  ];

  for (const item of replacements) {
    sanitized = sanitized.replace(item.target, item.replacement);
  }

  return `--- USER INPUT START ---\n${sanitized}\n--- USER INPUT END ---`;
}
