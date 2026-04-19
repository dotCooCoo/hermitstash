/**
 * Shared error types for consistent error handling across the app.
 *
 * Three distinct patterns, each with a specific purpose. Don't mix them.
 *
 *   1. AppError subclasses at domain boundaries.
 *      Business-logic failures that need to become HTTP responses throw one
 *      of the subclasses below. Each carries statusCode, code, and
 *      isAppError: true. Services and repositories use these.
 *
 *   2. Inline res.status().json() in route handlers for request-shape errors.
 *      Input validation against request params/body (wrong type, missing
 *      field, bad format) that's immediately translatable to a 4xx response
 *      stays in the route handler as:
 *          return res.status(400).json({ error: "..." });
 *      No reason to wrap that in a throw.
 *
 *   3. Plain `throw new Error(...)` only as internal control flow.
 *      try/catch blocks inside tight loops (e.g. per-file loops in storage
 *      migration) can throw to break out of an iteration and be counted in
 *      an aggregate result. These must always be caught locally — they
 *      never reach an HTTP response boundary.
 *
 * The shared error handler (middleware/error-handler.js) converts any
 * unhandled AppError to the appropriate HTTP response. Plain Error escapes
 * become 500s.
 */

class AppError extends Error {
  constructor(message, statusCode, code) {
    super(message);
    this.statusCode = statusCode || 500;
    this.code = code || "INTERNAL_ERROR";
    this.isAppError = true;
  }
}

class ValidationError extends AppError {
  constructor(message) { super(message, 400, "VALIDATION_ERROR"); }
}

class AuthenticationError extends AppError {
  constructor(message) { super(message || "Authentication required.", 401, "AUTH_REQUIRED"); }
}

class ForbiddenError extends AppError {
  constructor(message) { super(message || "Access denied.", 403, "FORBIDDEN"); }
}

class NotFoundError extends AppError {
  constructor(message) { super(message || "Not found.", 404, "NOT_FOUND"); }
}

class RateLimitError extends AppError {
  constructor(message, retryAfter) {
    super(message || "Too many requests.", 429, "RATE_LIMITED");
    this.retryAfter = retryAfter;
  }
}

class ConflictError extends AppError {
  constructor(message) { super(message || "Conflict.", 409, "CONFLICT"); }
}

module.exports = { AppError, ValidationError, AuthenticationError, ForbiddenError, NotFoundError, RateLimitError, ConflictError };
