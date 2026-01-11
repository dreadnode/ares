"""Tests for red team agent factory module."""

import time

from ares.core.factories.red_factory import (
    _should_log_event,
    reset_event_tracking,
)


class TestEventTracking:
    """Tests for event tracking functions."""

    def setup_method(self):
        """Reset event tracking before each test."""
        reset_event_tracking()

    def test_reset_event_tracking(self):
        """Test resetting event tracking state."""
        # Trigger an event to set state
        assert _should_log_event("test_event") is True

        # Reset and verify it allows logging again
        reset_event_tracking()
        assert _should_log_event("test_event") is True

    def test_should_log_event_first_call(self):
        """Test that first event always logs."""
        assert _should_log_event("new_event") is True

    def test_should_log_event_debounce(self):
        """Test that rapid duplicate events are debounced."""
        # First call should pass
        assert _should_log_event("rapid_event") is True

        # Second call within debounce window should be blocked
        assert _should_log_event("rapid_event") is False

    def test_should_log_event_different_types(self):
        """Test that different event types are tracked independently."""
        assert _should_log_event("event_a") is True
        assert _should_log_event("event_b") is True

    def test_should_log_event_after_debounce_window(self):
        """Test that events log again after debounce window."""
        # First call
        assert _should_log_event("timed_event") is True

        # Simulate passage of time by manipulating the internal state
        # This is a bit hacky but tests the time-based logic
        from ares.core.factories import red_factory

        red_factory._last_event_times["timed_event"] = time.time() - 1.0

        # After debounce window, should log again
        assert _should_log_event("timed_event") is True
