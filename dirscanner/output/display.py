"""
Rich-powered terminal display helpers.

Provides coloured output, progress bars, status indicators, and result
tables.  All finding display is severity-aware.  This module has no
side-effects on import — ``console`` is the single shared output handle.
"""

from pathlib import Path
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)
_err_console = Console(stderr=True, highlight=False)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = r"""
    ____  _      _____                                 
   / __ \(_)____/ ___/_________ _____  ____  ___  _____
  / / / / / ___/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /_/ / / /   ___/ / /__/ /_/ / / / / / / /  __/ /    
/_____/_/_/   /____/\___/\__,_/_/ |_/_/ /_/\___/_/     
                                            by SBK
"""


def print_banner() -> None:
    """Print the DirScanner ASCII banner to stdout."""
    console.print(
        Panel.fit(
            Align.center(Text(_BANNER.strip(), style="bold cyan")),
            subtitle="[dim]Directory Listing Scanner[/dim]",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# Severity colour / icon maps
# ---------------------------------------------------------------------------

SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "green",
    "info":     "dim",
}

SEVERITY_ICON: dict[str, str] = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}


# ---------------------------------------------------------------------------
# Scan-start info block
# ---------------------------------------------------------------------------


def print_scan_start(url: str, paths: int, threads: int, run_id: str) -> None:
    """Print the pre-scan configuration summary."""
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    table.add_column("key", style="dim")
    table.add_column("value", style="bold")
    table.add_row("Target",  f"[cyan]{url}[/cyan]")
    table.add_row("Paths",   str(paths))
    table.add_row("Threads", str(threads))
    table.add_row("Run ID",  run_id)

    console.print(Rule("[bold cyan]Scan Configuration[/bold cyan]"))
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------


class ScanProgress:
    """Context manager that owns a Rich progress bar for scan operations.

    Usage::

        with ScanProgress(total=1500) as prog:
            result = scan(..., progress_callback=prog.update)

    Args:
        total: Total number of paths to be probed (used to size the bar).
    """

    def __init__(self, total: int) -> None:
        self._total = total
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("• [bold green]{task.fields[found]} found[/bold green]"),
            console=console,
            transient=False,
        )
        self._task: TaskID | None = None

    def __enter__(self) -> "ScanProgress":
        self._progress.start()
        self._task = self._progress.add_task(
            "[cyan]Scanning…[/cyan]",
            total=self._total,
            found=0,
        )
        return self

    def update(self, processed: int, total: int, found: int) -> None:
        """Advance the progress bar.

        Args:
            processed: Number of probes completed so far.
            total: Total probes in this run (may change if paths were capped).
            found: Number of open directories detected so far.
        """
        if self._task is not None:
            self._progress.update(
                self._task,
                completed=processed,
                total=total,
                found=found,
            )

    def __exit__(self, *_: Any) -> None:
        self._progress.stop()


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------


def print_findings_table(findings: list[dict[str, Any]]) -> None:
    """Print a formatted table of scan findings (or a clean-bill panel).

    Args:
        findings: List of finding dicts from the report, as produced by
            :func:`~dirscanner.output.reporter.build_report`.
    """
    console.print()
    console.print(Rule("[bold yellow]Findings[/bold yellow]"))

    if not findings:
        console.print(
            Panel(
                "[bold green]✓  No open directory listings detected.[/bold green]",
                border_style="green",
            )
        )
        return

    suffix = "y" if len(findings) == 1 else "ies"
    table = Table(
        title=f"[bold red]{len(findings)} Open Director{suffix} Found[/bold red]",
        box=box.ROUNDED,
        show_lines=True,
        border_style="yellow",
        header_style="bold",
    )

    table.add_column("#",        style="dim",  width=4,   justify="right")
    table.add_column("URL",      style="cyan", min_width=40)
    table.add_column("Status",   justify="center", width=8)
    table.add_column("Severity", justify="center", width=12)

    for i, finding in enumerate(findings, start=1):
        sev = finding.get("severity", "info")
        sev_style = SEVERITY_STYLE.get(sev, "yellow")
        icon = SEVERITY_ICON.get(sev, "")
        status = finding.get("status_code", "?")

        table.add_row(
            str(i),
            finding.get("url", ""),
            f"[bold green]{status}[/bold green]",
            f"[{sev_style}]{icon} {sev.upper()}[/{sev_style}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Summary panel
# ---------------------------------------------------------------------------


def print_summary(report: dict[str, Any], run_dir: Path) -> None:
    """Print the post-scan summary and output file locations.

    Args:
        report: Complete report dict from
            :func:`~dirscanner.output.reporter.build_report`.
        run_dir: The run directory root (used to display output paths).
    """
    summary = report.get("summary", {})
    findings_count: int = summary.get("findings_count", 0)
    highest: str | None = summary.get("highest_severity")

    if findings_count:
        icon = SEVERITY_ICON.get(highest or "medium", "⚠")
        sev_style = SEVERITY_STYLE.get(highest or "medium", "yellow")
        outcome_text = (
            f"[{sev_style}]{icon}  {findings_count} finding(s) — "
            f"highest severity: {(highest or '?').upper()}[/{sev_style}]"
        )
    else:
        outcome_text = "[bold green]✓  Target appears clean[/bold green]"

    stats_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    stats_table.add_column("key",   style="dim")
    stats_table.add_column("value")
    stats_table.add_row("Outcome",        outcome_text)
    stats_table.add_row("Paths scanned",  str(summary.get("paths_scanned", "?")))
    stats_table.add_row("Elapsed",        f"{summary.get('elapsed_seconds', 0):.1f}s")
    stats_table.add_row("Timeouts",       str(summary.get("timeouts", 0)))
    stats_table.add_row("Request errors", str(summary.get("request_errors", 0)))

    if summary.get("aborted_early"):
        stats_table.add_row(
            "", "[yellow]⚡ Scan aborted early (sustained timeouts)[/yellow]"
        )

    breakdown: dict[str, int] = summary.get("severity_breakdown", {})
    if breakdown:
        stats_table.add_row("", "")
        stats_table.add_row("[dim]Severity breakdown[/dim]", "")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = breakdown.get(sev, 0)
            if count:
                sev_style = SEVERITY_STYLE.get(sev, "dim")
                icon = SEVERITY_ICON.get(sev, "")
                stats_table.add_row(
                    f"  {icon} {sev.capitalize()}",
                    f"[{sev_style}]{count}[/{sev_style}]",
                )

    files_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    files_table.add_column("label", style="dim")
    files_table.add_column("path",  style="cyan")
    files_table.add_row("Report",  str(run_dir / "report.json"))
    files_table.add_row("Run dir", str(run_dir))

    console.print()
    console.print(Rule("[bold cyan]Summary[/bold cyan]"))
    console.print(stats_table)
    console.print(Rule("[dim]Output files[/dim]"))
    console.print(files_table)
    console.print()


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------


def print_warning(msg: str) -> None:
    """Print a warning in yellow."""
    console.print(f"[yellow]⚠  {msg}[/yellow]")


def print_error(msg: str) -> None:
    """Print an error to stderr in bold red."""
    _err_console.print(f"[bold red]✖  {msg}[/bold red]")
