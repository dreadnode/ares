"""Custom exceptions for the Ares red team framework."""


class AresError(Exception):
    """Base error for all Ares-specific errors."""


class AuthenticationError(AresError):
    """Raised when authentication fails (invalid API key, unauthorized access, etc.).

    This is a critical error that should stop worker execution as the worker
    cannot complete its tasks without valid authentication.
    """

    def __init__(self, message: str, service: str | None = None, status_code: int | None = None):
        """Initialize authentication error.

        Args:
            message: Error message describing the authentication failure
            service: Optional service name (e.g., 'grafana', 'openai')
            status_code: Optional HTTP status code (e.g., 401, 403)
        """
        self.service = service
        self.status_code = status_code
        super().__init__(message)

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.service:
            parts.append(f"service={self.service}")
        if self.status_code:
            parts.append(f"status={self.status_code}")
        return f"AuthenticationError: {', '.join(parts)}"


class ConfigurationError(AresError):
    """Raised when required configuration is missing or invalid.

    This is a critical error that indicates the worker is misconfigured
    and cannot function properly.
    """


class CriticalWorkerError(AresError):
    """Raised when a worker encounters a fatal error that requires immediate attention.

    Workers should stop execution and not retry automatically when this is raised.
    """


class TaskExecutionError(AresError):
    """Raised when a task fails during execution but the worker can continue.

    This is a non-fatal error specific to a task. The worker can report
    the failure and move on to the next task.
    """


class AresConnectionError(AresError):
    """Raised when a connection to an external service fails.

    This is a potentially transient error. Workers may retry after a delay.
    """
