export class VibeShieldAuthorizationError extends Error {
  constructor(message: string) {
    super(`[VibeShield] Authorization Protection: ${message}`);
    this.name = 'VibeShieldAuthorizationError';
    Object.setPrototypeOf(this, VibeShieldAuthorizationError.prototype);
  }
}

export interface UserContext {
  id: string | number;
  role: 'admin' | 'user' | 'guest';
  permissions: string[];
}

export interface Finding {
  line: number;
  pattern: string;
  severity: 'critical' | 'high' | 'warning';
  suggestion: string;
  originalCode: string;
}

export interface DetectionResult {
  safe: boolean;
  findings: Finding[];
}

export const PERMISSION_MATRIX = {
  admin: {
    users: ['read', 'write', 'delete', 'admin'],
    posts: ['read', 'write', 'delete', 'admin'],
    settings: ['read', 'write', 'admin']
  },
  user: {
    users: ['read'],
    posts: ['read', 'write'],
    settings: ['read']
  },
  guest: {
    users: [],
    posts: ['read'],
    settings: []
  }
};

export function checkPermission(
  user: UserContext,
  resource: string,
  action: 'read' | 'write' | 'delete' | 'admin'
): boolean {
  if (user.role === 'admin') return true;

  const directPerm = `${resource}:${action}`;
  const directWildcard = `${resource}:*`;
  if (
    user.permissions.includes(directPerm) ||
    user.permissions.includes(directWildcard) ||
    user.permissions.includes('*:*')
  ) {
    return true;
  }

  const roleMatrix = PERMISSION_MATRIX[user.role];
  if (roleMatrix && (roleMatrix as any)[resource]) {
    const allowedActions = (roleMatrix as any)[resource];
    if (allowedActions.includes(action)) {
      return true;
    }
  }

  return false;
}

export function validateResourceOwnership(
  userId: string | number,
  resourceId: string | number,
  resourceOwnerId: string | number,
  userRole?: string
): boolean {
  if (userRole === 'admin') return true;
  return String(userId) === String(resourceOwnerId);
}

export function detectMissingAuthMiddleware(code: string): DetectionResult {
  const findings: Finding[] = [];
  if (!code) return { safe: true, findings };

  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];

    // Rule 1: Admin route missing auth middleware
    const isAdminRoute = /\.(get|post|put|delete|use|route)\s*\(\s*['"`]\/admin/i.test(line) || /@app\.(route|get|post|put|delete)\s*\(\s*['"`]\/admin/i.test(line);
    if (isAdminRoute) {
      const hasAuth = /requireAuth|requireRole|require_auth|require_role|Depends/i.test(line) ||
                      (i > 0 && /requireAuth|requireRole|require_auth|require_role/i.test(lines[i - 1]));
      if (!hasAuth) {
        findings.push({
          line: lineNum,
          pattern: 'Missing Auth in Admin Route',
          severity: 'critical',
          suggestion: 'Ensure an authorization middleware or role guard (e.g. requireRole(["admin"])) is applied to admin endpoints.',
          originalCode: line.trim()
        });
      }
    }

    // Rule 2: User/IDOR sensitive endpoints missing ownership check
    const isSensitiveUserRoute = /\/api\/users\/(:\w+|<\w+>)/i.test(line) || /\/posts\/(:\w+|<\w+>)/i.test(line);
    if (isSensitiveUserRoute) {
      const hasOwnership = /requireOwnership|require_ownership/i.test(line) ||
                           (i > 0 && /requireOwnership|require_ownership/i.test(lines[i - 1]));
      if (!hasOwnership) {
        findings.push({
          line: lineNum,
          pattern: 'Missing Ownership Check',
          severity: 'warning',
          suggestion: 'Ensure resource ownership validation (e.g. requireOwnership) is applied to prevent IDOR vulnerabilities.',
          originalCode: line.trim()
        });
      }
    }

    // Rule 3: Next.js HTTP method exports missing auth checks
    const isNextJsExport = /export\s+(const|async\s+function)\s+(DELETE|POST|PUT)\b/i.test(line);
    if (isNextJsExport) {
      // Check surrounding/inner lines or references (we check if auth keywords exist in the code file)
      const fileHasAuth = /requireAuth|requireRole|requirePermission|requireOwnership|checkPermission|validateResourceOwnership/i.test(code);
      if (!fileHasAuth) {
        findings.push({
          line: lineNum,
          pattern: 'Next.js HTTP Handler Missing Auth',
          severity: 'high',
          suggestion: 'Next.js HTTP handlers should enforce authentication/authorization checks inside the function block.',
          originalCode: line.trim()
        });
      }
    }
  }

  findings.sort((a, b) => a.line - b.line);
  return {
    safe: findings.length === 0,
    findings
  };
}
