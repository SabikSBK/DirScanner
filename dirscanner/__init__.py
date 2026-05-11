"""
DirScanner — Directory Listing Enabled Endpoint Detection.

A standalone local CLI tool that probes a target URL for open directory
listings and produces structured JSON reports alongside Rich terminal output.

Usage::

    python -m dirscanner scan https://example.com
    dirscanner scan https://example.com
"""

__version__ = "1.1.0"
__all__ = ["__version__"]
