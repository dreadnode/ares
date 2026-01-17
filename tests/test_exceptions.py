"""Tests for custom Ares exceptions."""

import pytest

from ares.core.exceptions import (
    AresConnectionError,
    AresError,
    AuthenticationError,
    ConfigurationError,
    CriticalWorkerError,
    TaskExecutionError,
)


class TestAresError:
    """Tests for base AresError."""

    def test_can_be_raised(self):
        """Test that AresError can be raised."""
        with pytest.raises(AresError):
            raise AresError("Test error")

    def test_inherits_from_exception(self):
        """Test that AresError inherits from Exception."""
        assert issubclass(AresError, Exception)

    def test_error_message(self):
        """Test error message is preserved."""
        msg = "Something went wrong"
        try:
            raise AresError(msg)
        except AresError as e:
            assert str(e) == msg


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_can_be_raised(self):
        """Test that AuthenticationError can be raised."""
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Auth failed")

    def test_inherits_from_ares_exception(self):
        """Test that AuthenticationError inherits from AresError."""
        assert issubclass(AuthenticationError, AresError)

    def test_basic_error_message(self):
        """Test basic error message without service or status."""
        msg = "Invalid credentials"
        err = AuthenticationError(msg)
        assert msg in str(err)

    def test_error_with_service(self):
        """Test error message includes service name."""
        err = AuthenticationError("Auth failed", service="grafana")
        error_str = str(err)
        assert "grafana" in error_str
        assert "service=grafana" in error_str

    def test_error_with_status_code(self):
        """Test error message includes status code."""
        err = AuthenticationError("Auth failed", status_code=401)
        error_str = str(err)
        assert "401" in error_str
        assert "status=401" in error_str

    def test_error_with_service_and_status(self):
        """Test error message includes both service and status."""
        err = AuthenticationError("Forbidden", service="openai", status_code=403)
        error_str = str(err)
        assert "openai" in error_str
        assert "403" in error_str
        assert "service=openai" in error_str
        assert "status=403" in error_str

    def test_attributes_are_accessible(self):
        """Test that service and status_code attributes are accessible."""
        err = AuthenticationError("Test", service="test-service", status_code=401)
        assert err.service == "test-service"
        assert err.status_code == 401

    def test_attributes_default_to_none(self):
        """Test that attributes default to None when not provided."""
        err = AuthenticationError("Test")
        assert err.service is None
        assert err.status_code is None

    def test_can_catch_as_ares_exception(self):
        """Test that AuthenticationError can be caught as AresError."""
        with pytest.raises(AresError):
            raise AuthenticationError("Test")


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_can_be_raised(self):
        """Test that ConfigurationError can be raised."""
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("Missing config")

    def test_inherits_from_ares_exception(self):
        """Test that ConfigurationError inherits from AresError."""
        assert issubclass(ConfigurationError, AresError)

    def test_error_message(self):
        """Test error message is preserved."""
        msg = "GRAFANA_API_KEY is not set"
        try:
            raise ConfigurationError(msg)
        except ConfigurationError as e:
            assert str(e) == msg

    def test_can_catch_as_ares_exception(self):
        """Test that ConfigurationError can be caught as AresError."""
        with pytest.raises(AresError):
            raise ConfigurationError("Test")


class TestCriticalWorkerError:
    """Tests for CriticalWorkerError."""

    def test_can_be_raised(self):
        """Test that CriticalWorkerError can be raised."""
        with pytest.raises(CriticalWorkerError):
            raise CriticalWorkerError("Critical failure")

    def test_inherits_from_ares_exception(self):
        """Test that CriticalWorkerError inherits from AresError."""
        assert issubclass(CriticalWorkerError, AresError)

    def test_error_message(self):
        """Test error message is preserved."""
        msg = "Fatal worker error requiring immediate attention"
        try:
            raise CriticalWorkerError(msg)
        except CriticalWorkerError as e:
            assert str(e) == msg

    def test_can_catch_as_ares_exception(self):
        """Test that CriticalWorkerError can be caught as AresError."""
        with pytest.raises(AresError):
            raise CriticalWorkerError("Test")


class TestTaskExecutionError:
    """Tests for TaskExecutionError."""

    def test_can_be_raised(self):
        """Test that TaskExecutionError can be raised."""
        with pytest.raises(TaskExecutionError):
            raise TaskExecutionError("Task failed")

    def test_inherits_from_ares_exception(self):
        """Test that TaskExecutionError inherits from AresError."""
        assert issubclass(TaskExecutionError, AresError)

    def test_error_message(self):
        """Test error message is preserved."""
        msg = "Failed to execute network scan task"
        try:
            raise TaskExecutionError(msg)
        except TaskExecutionError as e:
            assert str(e) == msg

    def test_can_catch_as_ares_exception(self):
        """Test that TaskExecutionError can be caught as AresError."""
        with pytest.raises(AresError):
            raise TaskExecutionError("Test")


class TestAresConnectionError:
    """Tests for AresConnectionError."""

    def test_can_be_raised(self):
        """Test that AresConnectionError can be raised."""
        with pytest.raises(AresConnectionError):
            raise AresConnectionError("Connection lost")

    def test_inherits_from_ares_exception(self):
        """Test that AresConnectionError inherits from AresError."""
        assert issubclass(AresConnectionError, AresError)

    def test_error_message(self):
        """Test error message is preserved."""
        msg = "Failed to connect to Redis"
        try:
            raise AresConnectionError(msg)
        except AresConnectionError as e:
            assert str(e) == msg

    def test_can_catch_as_ares_exception(self):
        """Test that AresConnectionError can be caught as AresError."""
        with pytest.raises(AresError):
            raise AresConnectionError("Test")


class TestExceptionHierarchy:
    """Tests for exception inheritance hierarchy."""

    def test_all_custom_exceptions_inherit_from_ares_exception(self):
        """Test that all custom exceptions inherit from AresError."""
        custom_exceptions = [
            AuthenticationError,
            ConfigurationError,
            CriticalWorkerError,
            TaskExecutionError,
            AresConnectionError,
        ]
        for exc_class in custom_exceptions:
            assert issubclass(exc_class, AresError)

    def test_can_catch_all_with_base_exception(self):
        """Test that AresError can catch all custom exceptions."""
        custom_exceptions = [
            AuthenticationError("test"),
            ConfigurationError("test"),
            CriticalWorkerError("test"),
            TaskExecutionError("test"),
            AresConnectionError("test"),
        ]
        for exc in custom_exceptions:
            with pytest.raises(AresError):
                raise exc


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
