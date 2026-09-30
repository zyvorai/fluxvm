// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

/** Base class for every error this package throws. */
export class FluxVMError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The API could not be reached (refused, DNS failure, TLS error, ...). */
export class ConnectionFailed extends FluxVMError {}

/** The API did not answer within the client-side timeout. */
export class RequestTimeout extends FluxVMError {}

/**
 * The API answered with a non-success status. `message` is the server's
 * `{"error": "..."}` text when the body had that shape, otherwise the raw body.
 * The server maps most handler failures (including guest-agent errors and
 * validation) to 400.
 */
export class ApiError extends FluxVMError {
  readonly status: number;
  readonly body: unknown;
  readonly detail: string;

  constructor(status: number, body: unknown, detail?: string) {
    const text = detail ?? (typeof body === "string" ? body : JSON.stringify(body));
    super(`HTTP ${status}: ${text}`);
    this.status = status;
    this.body = body;
    this.detail = text;
  }
}

/** 401: missing or invalid bearer token. */
export class AuthError extends ApiError {}

/**
 * 403: the token is valid but its role cannot call this route. Guest-reaching
 * sandbox routes (create, fs, process, snapshot, HTTP proxy) need an `admin`
 * token; `read-only` tokens get 403.
 */
export class ForbiddenError extends AuthError {}

/** 404. The API also answers 404 for another tenant's sandbox id. */
export class NotFound extends ApiError {}

/** 429. `retryAfter` is the server's Retry-After in seconds, if sent. */
export class RateLimited extends ApiError {
  readonly retryAfter?: number;

  constructor(status: number, body: unknown, detail?: string, retryAfter?: number) {
    super(status, body, detail);
    this.retryAfter = retryAfter;
  }
}
