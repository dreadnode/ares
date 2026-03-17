"""Small coverage-oriented smoke tests for public exceptions and exports."""

import ares
from ares.core.k8s_executor import PodExecutionError, PodNotAvailableError
from ares.core.query_resilience import QueryTimeoutError


def test_package_exposes_version_attribute():
    """Test the top-level package exposes a version string."""
    assert hasattr(ares, "__version__")
    assert isinstance(ares.__version__, str)


def test_custom_exception_messages_round_trip():
    """Test custom exception classes preserve their messages."""
    pod_not_available = PodNotAvailableError("missing pod")
    pod_execution = PodExecutionError("exec failed")
    query_timeout = QueryTimeoutError("timed out")

    assert str(pod_not_available) == "missing pod"
    assert str(pod_execution) == "exec failed"
    assert str(query_timeout) == "timed out"
