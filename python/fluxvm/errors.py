# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by the FluxVM client."""

from typing import Any, Optional


class FluxVMError(Exception):
    """Base class for every error this package raises."""


class ConnectionFailed(FluxVMError):
    """The API could not be reached (refused, DNS failure, TLS error, ...)."""


class RequestTimeout(FluxVMError):
    """The API did not answer within the client-side timeout."""


class ApiError(FluxVMError):
    """The API answered with a non-success status.

    ``message`` is the server's ``{"error": "..."}`` text when the body was
    that JSON shape, otherwise the raw body text. The server maps most
    handler failures (including guest-agent errors and validation) to 400.
    """

    def __init__(self, status: int, body: Any, message: Optional[str] = None):
        self.status = status
        self.body = body
        self.message = message if message is not None else str(body)
        super().__init__("HTTP {}: {}".format(status, self.message))


class AuthError(ApiError):
    """401: missing or invalid bearer token."""


class ForbiddenError(AuthError):
    """403: the token is valid but its role cannot call this route.

    Guest-reaching sandbox routes (create, fs, process, snapshot, HTTP proxy)
    need an ``admin`` token; ``read-only`` tokens get 403.
    """


class NotFound(ApiError):
    """404. The API also answers 404 for another tenant's sandbox id."""


class RateLimited(ApiError):
    """429. ``retry_after`` is the server's Retry-After in seconds, if sent."""

    def __init__(self, status: int, body: Any, message: Optional[str] = None,
                 retry_after: Optional[float] = None):
        super().__init__(status, body, message)
        self.retry_after = retry_after
