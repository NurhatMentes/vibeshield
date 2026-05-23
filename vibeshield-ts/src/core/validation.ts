import { ValidationSchema, ValidationRule } from '../types/index.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface ValidationResult {
  isValid: boolean;
  errors: Record<string, string> | null;
}

export function validatePayload(payload: any, schema: ValidationSchema): ValidationResult {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return { isValid: false, errors: { _root: 'Payload must be a JSON object' } };
  }

  const errors: Record<string, string> = {};

  function traverse(value: any, rule: ValidationRule, path: string) {
    const isMissing = value === undefined || value === null;

    if (isMissing) {
      if (rule.required) {
        errors[path] = `Field '${path}' is required`;
      }
      return;
    }

    // Determine actual type
    let actualType = typeof value;
    if (actualType === 'object') {
      if (Array.isArray(value)) actualType = 'array';
    }

    const expectedType = rule.type;
    if (actualType !== expectedType) {
      errors[path] = `Expected type '${expectedType}', but received '${actualType}'`;
      return;
    }

    // Primitive Constraints
    if (expectedType === 'string') {
      if (rule.min !== undefined && value.length < rule.min) {
        errors[path] = `String length must be at least ${rule.min} characters`;
      }
      if (rule.max !== undefined && value.length > rule.max) {
        errors[path] = `String length must not exceed ${rule.max} characters`;
      }
      if (rule.format === 'email' && !EMAIL_REGEX.test(value)) {
        errors[path] = 'Invalid email format';
      }
    } else if (expectedType === 'number') {
      if (rule.min !== undefined && value < rule.min) {
        errors[path] = `Value must be greater than or equal to ${rule.min}`;
      }
      if (rule.max !== undefined && value > rule.max) {
        errors[path] = `Value must be less than or equal to ${rule.max}`;
      }
    } else if (expectedType === 'array') {
      if (rule.min !== undefined && value.length < rule.min) {
        errors[path] = `Array must contain at least ${rule.min} items`;
      }
      if (rule.max !== undefined && value.length > rule.max) {
        errors[path] = `Array must not contain more than ${rule.max} items`;
      }
      
      // Recursive Traversal for Array Elements
      if (rule.elementSchema) {
        for (let i = 0; i < value.length; i++) {
          traverse(value[i], rule.elementSchema, `${path}[${i}]`);
        }
      }
    } else if (expectedType === 'object') {
      // Recursive Traversal for Object Properties
      if (rule.schema) {
        for (const [key, childRule] of Object.entries(rule.schema)) {
          traverse(value[key], childRule as ValidationRule, `${path}.${key}`);
        }
      }
    }
  }

  // Root traversal
  for (const [key, rule] of Object.entries(schema)) {
    traverse(payload[key], rule, key);
  }

  const hasErrors = Object.keys(errors).length > 0;
  return {
    isValid: !hasErrors,
    errors: hasErrors ? errors : null
  };
}
