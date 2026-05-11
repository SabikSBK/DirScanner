"""CLI entry point — exposes ``main()`` for the console script and ``-m`` invocation."""

from dirscanner.cli.commands import app


def main() -> None:
    """Entry point for the ``dirscanner`` console script."""
    app()


__all__ = ["app", "main"]
