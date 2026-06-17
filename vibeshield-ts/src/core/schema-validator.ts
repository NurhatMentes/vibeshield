export interface ValidationError {
  field: string;
  message: string;
  value?: any;
  expected?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  sanitizedData?: any;
}

export interface SchemaDefinition {
  [fieldName: string]: FieldSchema;
}

export interface FieldSchema {
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  required?: boolean;
  format?: 'email' | 'uuid' | 'url' | 'date' | 'phone' | 'ipv4' | 'ipv6';
  min?: number;
  max?: number;
  pattern?: RegExp;
  enum?: any[];
  schema?: SchemaDefinition;
  elementSchema?: FieldSchema;
  allowNull?: boolean;
  trim?: boolean;
}

export function validateSchema(data: unknown, schema: SchemaDefinition): ValidationResult {
  const errors: ValidationError[] = [];

  if (data === null || data === undefined || typeof data !== 'object' || Array.isArray(data)) {
    return {
      valid: false,
      errors: [{ field: '', message: 'Root data must be an object' }]
    };
  }

  const sanitizedData: any = {};

  // Strict whitelist check for unknown fields at root level
  const dataKeys = Object.keys(data as any);
  for (const key of dataKeys) {
    if (!(key in schema)) {
      errors.push({
        field: key,
        message: `Unknown field "${key}" is not allowed`,
        value: (data as any)[key]
      });
    }
  }

  // Validate expected fields
  for (const key of Object.keys(schema)) {
    const fieldSchema = schema[key];
    const value = (data as any)[key];
    validateField(value, fieldSchema, key, errors, sanitizedData, key);
  }

  return {
    valid: errors.length === 0,
    errors,
    sanitizedData: errors.length === 0 ? sanitizedData : undefined
  };
}

function validateField(
  value: any,
  fieldSchema: FieldSchema,
  path: string,
  errors: ValidationError[],
  parentSanitized: any,
  key: string
): void {
  // 1. Required & Nullability Checks
  if (value === undefined) {
    if (fieldSchema.required) {
      errors.push({ field: path, message: 'Field is required', expected: fieldSchema.type });
    }
    return;
  }

  if (value === null) {
    if (fieldSchema.allowNull) {
      parentSanitized[key] = null;
    } else {
      errors.push({ field: path, message: 'Value cannot be null', value, expected: fieldSchema.type });
    }
    return;
  }

  const { type } = fieldSchema;

  // 2. Strict Type Checking (no type coercion)
  if (type === 'string') {
    if (typeof value !== 'string') {
      errors.push({ field: path, message: `Expected type string, got ${typeof value}`, value, expected: 'string' });
      return;
    }
    if (fieldSchema.trim) {
      value = value.trim();
    }
  } else if (type === 'number') {
    if (typeof value !== 'number' || Number.isNaN(value)) {
      errors.push({ field: path, message: `Expected type number, got ${typeof value}`, value, expected: 'number' });
      return;
    }
  } else if (type === 'boolean') {
    if (typeof value !== 'boolean') {
      errors.push({ field: path, message: `Expected type boolean, got ${typeof value}`, value, expected: 'boolean' });
      return;
    }
  } else if (type === 'object') {
    if (typeof value !== 'object' || Array.isArray(value) || value === null) {
      errors.push({ field: path, message: `Expected type object, got ${Array.isArray(value) ? 'array' : typeof value}`, value, expected: 'object' });
      return;
    }
  } else if (type === 'array') {
    if (!Array.isArray(value)) {
      errors.push({ field: path, message: `Expected type array, got ${typeof value}`, value, expected: 'array' });
      return;
    }
  }

  // 3. Min/Max Checks
  if (type === 'string') {
    if (fieldSchema.min !== undefined && value.length < fieldSchema.min) {
      errors.push({ field: path, message: `Length must be at least ${fieldSchema.min}`, value });
    }
    if (fieldSchema.max !== undefined && value.length > fieldSchema.max) {
      errors.push({ field: path, message: `Length must be at most ${fieldSchema.max}`, value });
    }
  } else if (type === 'number') {
    if (fieldSchema.min !== undefined && value < fieldSchema.min) {
      errors.push({ field: path, message: `Value must be at least ${fieldSchema.min}`, value });
    }
    if (fieldSchema.max !== undefined && value > fieldSchema.max) {
      errors.push({ field: path, message: `Value must be at most ${fieldSchema.max}`, value });
    }
  } else if (type === 'array') {
    if (fieldSchema.min !== undefined && value.length < fieldSchema.min) {
      errors.push({ field: path, message: `Array must contain at least ${fieldSchema.min} items`, value });
    }
    if (fieldSchema.max !== undefined && value.length > fieldSchema.max) {
      errors.push({ field: path, message: `Array must contain at most ${fieldSchema.max} items`, value });
    }
  }

  // 4. Format Checks
  if (type === 'string' && fieldSchema.format) {
    let valid = true;
    if (fieldSchema.format === 'email') {
      valid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
    } else if (fieldSchema.format === 'uuid') {
      valid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
    } else if (fieldSchema.format === 'url') {
      valid = /^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(value);
    } else if (fieldSchema.format === 'ipv4') {
      valid = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(value);
    } else if (fieldSchema.format === 'ipv6') {
      valid = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(value);
    } else if (fieldSchema.format === 'phone') {
      valid = /^\+?[1-9]\d{1,14}$/.test(value);
    } else if (fieldSchema.format === 'date') {
      valid = !isNaN(Date.parse(value)) && /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$/.test(value);
    }
    if (!valid) {
      errors.push({ field: path, message: `Invalid ${fieldSchema.format} format`, value });
    }
  }

  // 5. Pattern Check
  if (type === 'string' && fieldSchema.pattern) {
    if (!fieldSchema.pattern.test(value)) {
      errors.push({ field: path, message: `Value does not match pattern: ${fieldSchema.pattern.toString()}`, value });
    }
  }

  // 6. Enum Check
  if (fieldSchema.enum) {
    if (!fieldSchema.enum.includes(value)) {
      errors.push({ field: path, message: `Value must be one of: [${fieldSchema.enum.join(', ')}]`, value });
    }
  }

  // 7. Recursive Object Validation
  if (type === 'object') {
    if (fieldSchema.schema) {
      const subSanitized: any = {};
      const subKeys = Object.keys(value);
      for (const subKey of subKeys) {
        if (!(subKey in fieldSchema.schema)) {
          errors.push({
            field: `${path}.${subKey}`,
            message: `Unknown field "${subKey}" is not allowed`,
            value: value[subKey]
          });
        }
      }

      for (const subKey of Object.keys(fieldSchema.schema)) {
        const subFieldSchema = fieldSchema.schema[subKey];
        const subValue = value[subKey];
        validateField(subValue, subFieldSchema, `${path}.${subKey}`, errors, subSanitized, subKey);
      }
      parentSanitized[key] = subSanitized;
    } else {
      parentSanitized[key] = { ...value };
    }
    return;
  }

  // 8. Recursive Array Element Validation
  if (type === 'array') {
    if (fieldSchema.elementSchema) {
      const subSanitized: any[] = [];
      for (let i = 0; i < value.length; i++) {
        const elementPath = `${path}[${i}]`;
        const elementValue = value[i];
        const tempParent: any = {};
        validateField(elementValue, fieldSchema.elementSchema, elementPath, errors, tempParent, 'element');
        subSanitized.push(tempParent.element);
      }
      parentSanitized[key] = subSanitized;
    } else {
      parentSanitized[key] = [...value];
    }
    return;
  }

  parentSanitized[key] = value;
}
