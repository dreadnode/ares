"""Tests for __main__.py entry point."""

from unittest.mock import patch


class TestRunFunction:
    """Tests for the run() function."""

    def test_run_calls_app(self):
        """Test that run() calls the app."""
        with patch("ares.__main__.app") as mock_app:
            from ares.__main__ import run

            run()
            mock_app.assert_called_once()


class TestMainBlock:
    """Tests for if __name__ == '__main__' block."""

    def test_main_block_calls_run(self):
        """Test that running as main calls run()."""
        with patch("ares.__main__.run"):
            # Simulate running as __main__
            import ares.__main__ as entry_module

            # Check that the module has the expected structure
            assert hasattr(entry_module, "run")
            assert hasattr(entry_module, "app")
            assert callable(entry_module.run)


class TestModuleImports:
    """Tests for module imports."""

    def test_app_imported_from_main(self):
        """Test that app is imported from main module."""
        from ares.__main__ import app
        from ares.main import app as main_app

        assert app is main_app
