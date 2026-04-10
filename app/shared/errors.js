/**
 * Shared error types for consistent error handling across the app.
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
