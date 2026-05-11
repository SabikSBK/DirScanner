"""Output layer — JSON report generation and Rich terminal display."""

from dirscanner.output.reporter import RunDirectory, build_report
from dirscanner.output.display import (
    ScanProgress,
    console,
    print_banner,
    print_error,
    print_findings_table,
    print_scan_start,
    print_summary,
    print_warning,
)

__all__ = [
    "RunDirectory",
    "build_report",
    "ScanProgress",
    "console",
    "print_banner",
    "print_error",
    "print_findings_table",
    "print_scan_start",
    "print_summary",
    "print_warning",
]
