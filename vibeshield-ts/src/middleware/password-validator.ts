import { validatePassword, PasswordPolicyOptions } from '../core/password-protector.js';

export function validatePasswordMiddleware(options?: PasswordPolicyOptions) {
  return (req: any, res?: any, next?: any) => {
    // Next.js Route Handler Wrapper check: arg1 is a function
    if (typeof req === 'function') {
      const handler = req;
      return async (webReq: any, ...args: any[]) => {
        let body: any = {};
        if (webReq && typeof webReq.json === 'function') {
          try {
            const clone = webReq.clone();
            body = await clone.json();
          } catch (e) {
            body = {};
          }
        }
        const password = body.password;
        const context = body.context || {
          username: body.username,
          email: body.email,
          firstName: body.firstName,
          lastName: body.lastName,
          birthDate: body.birthDate
        };

        const result = validatePassword(password, context, options);
        if (!result.valid) {
          return new Response(
            JSON.stringify({
              error: 'Bad Request',
              message: 'Password does not meet security requirements',
              details: result
            }),
            {
              status: 400,
              headers: { 'Content-Type': 'application/json' }
            }
          );
        }

        return handler(webReq, ...args);
      };
    }

    // Express middleware
    const password = req.body?.password;
    const context = req.body?.context || {
      username: req.body?.username,
      email: req.body?.email,
      firstName: req.body?.firstName,
      lastName: req.body?.lastName,
      birthDate: req.body?.birthDate
    };

    const result = validatePassword(password, context, options);
    if (!result.valid) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Password does not meet security requirements',
        details: result
      });
    }

    if (typeof next === 'function') {
      next();
    }
  };
}
