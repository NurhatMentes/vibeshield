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

export interface PermissionMatrix {
  [role: string]: {
    [resource: string]: string[];
  };
}

export const DEFAULT_PERMISSION_MATRIX: PermissionMatrix = {
  admin: {
    users: ['read', 'write', 'delete', 'admin'],
    posts: ['read', 'write', 'delete', 'admin'],
    settings: ['read', 'write', 'admin'],
  },
  user: {
    users: ['read'],
    posts: ['read', 'write'],
    settings: ['read'],
  },
  guest: {
    posts: ['read'],
  },
};

export const PERMISSION_MATRIX = DEFAULT_PERMISSION_MATRIX;

export function createPermissionMatrix(customMatrix: PermissionMatrix): PermissionMatrix {
  const merged: PermissionMatrix = {};
  
  for (const [role, resources] of Object.entries(DEFAULT_PERMISSION_MATRIX)) {
    merged[role] = { ...resources };
  }
  
  for (const [role, resources] of Object.entries(customMatrix)) {
    merged[role] = {
      ...(merged[role] || {}),
      ...resources,
    };
  }
  
  return merged;
}

export function checkPermission(
  userOrRole: UserContext | string,
  resource: string,
  action: string,
  matrix: PermissionMatrix = DEFAULT_PERMISSION_MATRIX
): boolean {
  let userRole: string;
  let permissions: string[] = [];

  if (typeof userOrRole === 'object' && userOrRole !== null) {
    userRole = userOrRole.role;
    permissions = userOrRole.permissions || [];
  } else {
    userRole = userOrRole;
  }

  if (userRole === 'admin') return true;

  if (permissions.length > 0) {
    const directPerm = `${resource}:${action}`;
    const directWildcard = `${resource}:*`;
    if (
      permissions.includes(directPerm) ||
      permissions.includes(directWildcard) ||
      permissions.includes('*:*')
    ) {
      return true;
    }
  }

  const rolePermissions = matrix[userRole];
  if (!rolePermissions) return false;
  
  const resourcePermissions = rolePermissions[resource];
  if (!resourcePermissions) return false;
  
  return resourcePermissions.includes(action) || resourcePermissions.includes('admin');
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
