"""
DirScanner CLI — Typer + Rich interface.

Entry points::

    python -m dirscanner scan <url>
    dirscanner scan <url>

Exit codes:
    0 — scan completed, no findings
    1 — scan completed, findings detected
    2 — fatal error (bad URL, missing file, filesystem error, etc.)
    3 — target unreachable (all probes failed)
"""

import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Annotated

import typer

from dirscanner.core.directorylist import DIRECTORIES
from dirscanner.core.scanner import ScanConfig, scan, validate_url
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
from dirscanner.output.reporter import RunDirectory, build_report

app = typer.Typer(
    name="dirscanner",
    help="[bold cyan]DirScanner[/bold cyan] — Directory Listing Enabled Endpoint Detection",
    rich_markup_mode="rich",
    add_completion=False,
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def _setup_logging(verbose: bool, log_file: Path) -> None:
    """Configure the root ``dirscanner`` logger.

    Debug output goes to stderr only when ``--verbose`` is set.  The log
    file always receives DEBUG-level records regardless of verbosity.

    Args:
        verbose: When ``True``, stream DEBUG logs to stderr.
        log_file: Path to the per-run log file (always written).
    """
    handlers: list[logging.Handler] = []

    if verbose:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        handlers.append(stream_handler)

    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        handlers.append(file_handler)
    except OSError as exc:
        print_warning(f"Could not open log file {log_file}: {exc}")

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        handlers=handlers,
        force=True,
    )


# ---------------------------------------------------------------------------
# `scan` command
# ---------------------------------------------------------------------------


@app.command(name="scan")
def cmd_scan(
    url: Annotated[
        str,
        typer.Argument(help="Target URL to scan (e.g. https://example.com)"),
    ],

    # ---- Output ----
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir", "-o",
            help="Root directory for scan output.",
            show_default=True,
        ),
    ] = Path("./dirscanner-output"),

    run_id: Annotated[
        str | None,
        typer.Option("--run-id", help="Custom run identifier (default: random UUID)."),
    ] = None,

    # ---- Scan behaviour ----
    threads: Annotated[
        int,
        typer.Option("--threads", "-t", help="Concurrent threads.", show_default=True),
    ] = 8,

    timeout: Annotated[
        int,
        typer.Option("--timeout", help="HTTP request timeout (seconds).", show_default=True),
    ] = 7,

    retries: Annotated[
        int,
        typer.Option("--retries", help="Retry count per request.", show_default=True),
    ] = 0,

    max_paths: Annotated[
        int,
        typer.Option("--max-paths", help="Limit paths probed (0 = all).", show_default=True),
    ] = 0,

    delay_min: Annotated[
        float,
        typer.Option("--delay-min", help="Minimum per-request delay (seconds).", show_default=True),
    ] = 0.1,

    delay_max: Annotated[
        float,
        typer.Option("--delay-max", help="Maximum per-request delay (seconds).", show_default=True),
    ] = 0.4,

    custom_paths: Annotated[
        list[str] | None,
        typer.Option("--path", "-p", help="Extra path(s) to probe (repeatable)."),
    ] = None,

    paths_file: Annotated[
        Path | None,
        typer.Option("--paths-file", help="File containing one path per line."),
    ] = None,

    wordlist_only: Annotated[
        bool,
        typer.Option("--wordlist-only", help="Skip user-supplied paths; use only the built-in wordlist."),
    ] = False,

    no_base_url: Annotated[
        bool,
        typer.Option("--no-base-url", help="Skip probing the root / path."),
    ] = False,

    # ---- Misc ----
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable debug logging to stderr."),
    ] = False,

    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress progress; print open URLs only."),
    ] = False,

    no_banner: Annotated[
        bool,
        typer.Option("--no-banner", help="Skip the ASCII banner."),
    ] = False,
) -> None:
    """Scan a URL for open directory listings.

    Examples:

      dirscanner scan https://example.com

      dirscanner scan https://example.com --threads 16 --timeout 10

      dirscanner scan https://example.com -p /backup/ -p /uploads/

      dirscanner scan https://example.com --paths-file wordlist.txt

      dirscanner scan https://example.com --max-paths 500 --quiet
    """
    if not quiet and not no_banner:
        print_banner()

    # -- Validate URL --------------------------------------------------------
    validated = validate_url(url)
    if not validated:
        print_error(f"Invalid URL: {url!r}  (must be http/https with a valid hostname)")
        raise typer.Exit(code=2)

    # -- Validate numeric options --------------------------------------------
    if threads < 1:
        print_error("--threads must be at least 1")
        raise typer.Exit(code=2)
    if timeout < 1:
        print_error("--timeout must be at least 1")
        raise typer.Exit(code=2)
    if delay_min < 0 or delay_max < 0:
        print_error("--delay-min and --delay-max must be non-negative")
        raise typer.Exit(code=2)
    if delay_min > delay_max:
        print_error("--delay-min must not exceed --delay-max")
        raise typer.Exit(code=2)

    # -- Run ID and output directories ---------------------------------------
    effective_run_id = run_id or str(uuid.uuid4())

    try:
        run_dir = RunDirectory(root=output_dir, run_id=effective_run_id)
    except OSError as exc:
        print_error(f"Cannot create output directory {output_dir}: {exc}")
        raise typer.Exit(code=2)

    _setup_logging(verbose, run_dir.log_file)

    # -- Merge extra paths ---------------------------------------------------
    extra_paths: list[str] = list(custom_paths or [])

    if paths_file is not None:
        if not paths_file.exists():
            print_error(f"Paths file not found: {paths_file}")
            raise typer.Exit(code=2)
        try:
            lines = paths_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            print_error(f"Cannot read paths file {paths_file}: {exc}")
            raise typer.Exit(code=2)
        extra_paths.extend(line for line in lines if line.strip())

    # -- Build config --------------------------------------------------------
    cfg = ScanConfig(
        threads=threads,
        timeout=timeout,
        retries=retries,
        min_delay=delay_min,
        max_delay=delay_max,
        wordlist_only=wordlist_only,
        max_paths=max_paths,
        scan_base_url=not no_base_url,
    )

    # -- Estimate total paths for progress bar -------------------------------
    extra_normalised = {p.strip("/") for p in extra_paths if p.strip()}
    if not cfg.wordlist_only:
        total_paths = len(extra_normalised | {d.strip("/") for d in DIRECTORIES})
    else:
        total_paths = len(DIRECTORIES)
    if cfg.max_paths > 0:
        total_paths = min(total_paths, cfg.max_paths)
    if cfg.scan_base_url:
        total_paths += 1

    if not quiet:
        print_scan_start(validated, total_paths, threads, effective_run_id)

    # -- Run scan ------------------------------------------------------------
    if quiet:
        result = scan(base_url=validated, cfg=cfg, extra_paths=extra_paths)
    else:
        with ScanProgress(total=total_paths) as prog:
            result = scan(
                base_url=validated,
                cfg=cfg,
                extra_paths=extra_paths,
                progress_callback=prog.update,
            )

    # -- Check for total network failure -------------------------------------
    if result.stats.processed > 0 and result.stats.failures >= result.stats.processed:
        print_error(
            f"Target appears unreachable — "
            f"{result.stats.timeouts} timeout(s), "
            f"{result.stats.request_errors} error(s) "
            f"across {result.stats.processed} probe(s)."
        )
        raise typer.Exit(code=3)

    # -- Build and write report ----------------------------------------------
    try:
        report = build_report(result=result, run_id=effective_run_id, run_dir=run_dir)
    except OSError as exc:
        print_error(f"Failed to write report: {exc}")
        raise typer.Exit(code=2)

    # -- Display results -----------------------------------------------------
    if not quiet:
        print_findings_table(report.get("findings", []))
        print_summary(report, run_dir.root)
    else:
        for finding in report.get("findings", []):
            console.print(finding["url"])

    raise typer.Exit(code=1 if report["summary"]["findings_count"] > 0 else 0)


# ---------------------------------------------------------------------------
# `report` command
# ---------------------------------------------------------------------------


@app.command(name="report")
def cmd_report(
    report_file: Annotated[
        Path,
        typer.Argument(help="Path to a dirscanner report.json file."),
    ],
    no_banner: Annotated[
        bool,
        typer.Option("--no-banner", help="Skip the ASCII banner."),
    ] = False,
) -> None:
    """Pretty-print an existing scan report.

    Useful for reviewing a previous scan without re-running it.

    Example:

      dirscanner report ./dirscanner-output/<run-id>/report.json
    """
    if not no_banner:
        print_banner()

    if not report_file.exists():
        print_error(f"Report not found: {report_file}")
        raise typer.Exit(code=2)

    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print_error(f"Failed to parse report: {exc}")
        raise typer.Exit(code=2)

    print_findings_table(report.get("findings", []))
    print_summary(report, report_file.parent)


# ---------------------------------------------------------------------------
# `version` command
# ---------------------------------------------------------------------------


@app.command(name="version")
def cmd_version() -> None:
    """Print the installed dirscanner version."""
    try:
        from importlib.metadata import version
        ver = version("dirscanner")
    except Exception:
        from dirscanner import __version__
        ver = __version__
    console.print(f"dirscanner [bold cyan]{ver}[/bold cyan]")
