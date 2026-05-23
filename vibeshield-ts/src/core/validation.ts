import { ValidationSchema, ValidationRule } from '../types';

export interface ValidationResult {
  isValid: boolean;
  errors: Record<string, string> | null;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validatePayload(payload: any, schema: ValidationSchema): ValidationResult {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return {
      isValid: false,
      errors: { _root: 'Payload must be a JSON object' }
    };
  }

  const errors: Record<string, string> = {};
  let hasErrors = false;

  for (const [key, rule] of Object.entries(schema)) {
    const value = payload[key];
    const isMissing = value === undefined || value === null;

    if (isMissing) {
      if (rule.required) {
        errors[key] = `Field '${key}' is required`;
        hasErrors = true;
      }
      continue;
    }

    // Type Validation
    let actualType = typeof value;
    if (actualType === 'object') {
      if (Array.isArray(value)) {
        actualType = 'array' as any;
      }
    }

    if (actualType !== rule.type) {
      errors[key] = `Expected type '${rule.type}', but received '${actualType}'`;
      hasErrors = true;
      continue;
    }

    // Constraints Validation
    if (rule.type === 'string') {
      const strVal = value as string;
      if (rule.min !== undefined && strVal.length < rule.min) {
        errors[key] = `String length must be at least ${rule.min} characters`;
        hasErrors = true;
      }
      if (rule.max !== undefined && strVal.length > rule.max) {
        errors[key] = `String length must not exceed ${rule.max} characters`;
        hasErrors = true;
      }
      if (rule.format === 'email' && !EMAIL_REGEX.test(strVal)) {
        errors[key] = `Invalid email format`;
        hasErrors = true;
      }
    } else if (rule.type === 'number') {
      const numVal = value as number;
      if (rule.min !== undefined && numVal < rule.min) {
        errors[key] = `Value must be greater than or equal to ${rule.min}`;
        hasErrors = true;
      }
      if (rule.max !== undefined && numVal > rule.max) {
        errors[key] = `Value must be less than or equal to ${rule.max}`;
        hasErrors = true;
      }
    } else if (rule.type === 'array') {
      const arrVal = value as any[];
      if (rule.min !== undefined && arrVal.length < rule.min) {
        errors[key] = `Array must contain at least ${rule.min} items`;
        hasErrors = true;
      }
      if (rule.max !== undefined && arrVal.length > rule.max) {
        errors[key] = `Array must not contain more than ${rule.max} items`;
        hasErrors = true;
      }
    }
  }

  return {
    isValid: !hasErrors,
    errors: hasErrors ? errors : null
  };
}
