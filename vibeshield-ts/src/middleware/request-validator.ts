import { validateSchema, SchemaDefinition } from '../core/schema-validator.js';

export function validateRequest(schema: SchemaDefinition) {
  return (arg1: any, arg2?: any, arg3?: any) => {
    // Next.js Route Handler Wrapper check: arg1 is a function
    if (typeof arg1 === 'function') {
      const handler = arg1;
      return async (req: any, ...args: any[]) => {
        let body: any = {};
        if (req && typeof req.json === 'function') {
          try {
            const clone = req.clone();
            body = await clone.json();
          } catch (e) {
            body = {};
          }
        }
        let query: any = {};
        if (req && req.url) {
          try {
            const url = new URL(req.url);
            query = Object.fromEntries(url.searchParams.entries());
          } catch (e) {
            query = {};
          }
        }

        const dataToValidate = { ...query, ...body };
        const result = validateSchema(dataToValidate, schema);
        if (!result.valid) {
          return new Response(
            JSON.stringify({
              error: 'Bad Request',
              message: 'Schema validation failed',
              errors: result.errors
            }),
            {
              status: 400,
              headers: { 'Content-Type': 'application/json' }
            }
          );
        }

        (req as any).sanitizedBody = result.sanitizedData;
        return handler(req, ...args);
      };
    }

    // Express middleware
    const req = arg1;
    const res = arg2;
    const next = arg3;

    const dataToValidate = {
      ...req.params,
      ...req.query,
      ...req.body
    };

    const result = validateSchema(dataToValidate, schema);
    if (!result.valid) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Schema validation failed',
        errors: result.errors
      });
    }

    req.sanitizedBody = result.sanitizedData;
    if (req.body) {
      req.body = result.sanitizedData;
    }

    if (typeof next === 'function') {
      next();
    }
  };
}
