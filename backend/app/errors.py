"""
Application exceptions and standardized error codes.

Routes and services raise :class:`ApiError` for expected failures. A single
centralized error handler (see ``app/middleware/error_handler.py``) converts
them into the consistent JSON error envelope.
"""


class ApiError(Exception):
    """Expected application error mapped to a JSON response."""

    def __init__(self, message, status_code=400, code="BAD_REQUEST", details=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.details = details


class BadRequestError(ApiError):
    def __init__(self, message="Bad request", details=None):
        super().__init__(message, status_code=400, code="BAD_REQUEST", details=details)


class ValidationError(ApiError):
    def __init__(self, message="Invalid input", details=None):
        super().__init__(message, status_code=400, code="VALIDATION_ERROR", details=details)


class UnauthorizedError(ApiError):
    def __init__(self, message="Authentication required", details=None):
        super().__init__(message, status_code=401, code="UNAUTHORIZED", details=details)


class ForbiddenError(ApiError):
    def __init__(self, message="Access denied", details=None):
        super().__init__(message, status_code=403, code="FORBIDDEN", details=details)


class NotFoundError(ApiError):
    def __init__(self, message="Resource not found", details=None):
        super().__init__(message, status_code=404, code="NOT_FOUND", details=details)


class PayloadTooLargeError(ApiError):
    def __init__(self, message="Request payload too large", details=None):
        super().__init__(message, status_code=413, code="PAYLOAD_TOO_LARGE", details=details)


class ServiceUnavailableError(ApiError):
    """Raised when a required subsystem (DB, ML) is not yet available."""

    def __init__(self, message="Service currently unavailable", code="SERVICE_UNAVAILABLE", details=None):
        super().__init__(message, status_code=503, code=code, details=details)


class FeatureUnavailableError(ApiError):
    """Raised when a feature is deferred to a later implementation phase."""

    def __init__(self, message="Feature is not yet available", code="FEATURE_UNAVAILABLE", details=None):
        super().__init__(message, status_code=501, code=code, details=details)
