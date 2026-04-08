"""Package entry point for the Ares command-line interface."""

import warnings

from .main import app


def run() -> None:
    """Run the package CLI entry point."""
    warnings.warn(
        "The 'ares' Python CLI is deprecated. Use the Rust CLI binary 'ares' instead. "
        "See NEW-RUST-TODO.md for details.",
        DeprecationWarning,
        stacklevel=2,
    )
    app()


if __name__ == "__main__":
    run()
