"""
Output module — structured JSON report generation and local file artefacts.

Each scan creates a timestamped run directory under the configured output
root::

    <output_root>/<run_id>/
        report.json      — structured findings report (schema v1.1)
        dirscanner.log   — full debug log for this run
        raw_req/         — per-finding HTTP request JSON
        raw_res/         — per-finding HTTP response JSON

No external services are required; all output is written locally.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dirscanner.core.scanner import Probe, ScanResult
from dirscanner.core.severity import classify_severity


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sanitize(value: str) -> str:
    """Return *value* safe for use as a filename stem.

    Replaces any character that is not alphanumeric, a dot, a hyphen, or an
    underscore with ``_``.  Falls back to ``"unknown"`` for empty results.
    """
    sanitised = re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_")
    return sanitised or "unknown"


def _sha256(*parts: str) -> str:
    """Return the SHA-256 hex digest of all *parts* joined by ``|``."""
    combined = "|".join(str(p) for p in parts)
    return hashlib.sha256(combined.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Run directory layout
# ---------------------------------------------------------------------------

# Severity levels from highest to lowest — used for summary ordering.
_SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]


class RunDirectory:
    """Manages the local artefact directory tree for one scan run.

    Creates the following layout on initialisation::

        <root>/<run_id>/
            raw_req/
            raw_res/

    Args:
        root: Parent directory for all scan outputs.
        run_id: Unique identifier for this run (used as the sub-directory name).
    """

    def __init__(self, root: Path, run_id: str) -> None:
        self.root: Path = root / run_id
        self.raw_req: Path = self.root / "raw_req"
        self.raw_res: Path = self.root / "raw_res"
        self.log_file: Path = self.root / "dirscanner.log"
        self.report_file: Path = self.root / "report.json"

        for directory in (self.root, self.raw_req, self.raw_res):
            directory.mkdir(parents=True, exist_ok=True)

    def write_json(self, path: Path, data: Any) -> None:
        """Serialise *data* to *path* as pretty-printed UTF-8 JSON."""
        with path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    def write_probe_artefacts(self, index: int, probe: Probe) -> tuple[Path, Path]:
        """Write raw request and response JSON files for *probe*.

        Files are named ``<index>-<sanitised_path>.json`` and placed in
        the ``raw_req/`` and ``raw_res/`` sub-directories respectively.

        Args:
            index: 1-based probe index (used for filename ordering).
            probe: The completed :class:`~dirscanner.core.scanner.Probe`.

        Returns:
            ``(request_path, response_path)`` for both artefact files.
        """
        stem = f"{index:04d}-{_sanitize(probe.path)}"
        req_path = self.raw_req / f"{stem}.json"
        res_path = self.raw_res / f"{stem}.json"

        self.write_json(
            req_path,
            {
                "method": "GET",
                "url": probe.target,
                "headers": {"User-Agent": probe.user_agent},
            },
        )
        self.write_json(
            res_path,
            {
                "status_code": probe.status_code,
                "headers": probe.response_headers,
                "body": probe.response_body,
            },
        )
        return req_path, res_path


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------


def build_report(
    result: ScanResult,
    run_id: str,
    run_dir: RunDirectory,
) -> dict[str, Any]:
    """Build and persist the structured JSON report for a completed scan.

    Writes ``report.json`` into *run_dir* and returns the report dict.

    Each confirmed open-directory probe produces one finding entry with:

    - A stable ``fingerprint`` (SHA-256 of tool + base URL + finding URL).
    - Severity classification via :func:`~dirscanner.core.severity.classify_severity`.
    - Relative paths to the raw request/response artefact files.
    - Actionable remediation guidance.

    Args:
        result: :class:`~dirscanner.core.scanner.ScanResult` from the engine.
        run_id: Unique identifier for this run.
        run_dir: :class:`RunDirectory` managing the output tree.

    Returns:
        The complete report dict (also written to ``run_dir.report_file``).
    """
    findings: list[dict[str, Any]] = []

    for idx, probe in enumerate(result.probes, start=1):
        if not probe.open or probe.status_code != 200:
            continue

        req_path, res_path = run_dir.write_probe_artefacts(idx, probe)
        severity = classify_severity(probe.path)

        findings.append(
            {
                "instance_id": str(uuid.uuid4()),
                "fingerprint": _sha256("dirscanner", result.base_url, probe.target),
                "url": probe.target,
                "path": probe.path,
                "status_code": probe.status_code,
                "severity": severity,
                "title": "Directory Listing Enabled",
                "description": (
                    "The web server exposes an open directory index at this path, "
                    "allowing unauthenticated users to browse and download files."
                ),
                "remediation": (
                    "Disable directory listing in your web server configuration "
                    "(e.g. `Options -Indexes` in Apache, `autoindex off` in Nginx)."
                ),
                "artefacts": {
                    "request": str(req_path.relative_to(run_dir.root)),
                    "response": str(res_path.relative_to(run_dir.root)),
                },
            }
        )

    # Severity breakdown
    severity_counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for finding in findings:
        sev = finding.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    highest_severity: str | None = next(
        (s for s in _SEVERITY_ORDER if severity_counts.get(s, 0) > 0),
        None,
    )

    report: dict[str, Any] = {
        "schema_version": "1.1",
        "tool": "dirscanner",
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_fingerprint": _sha256("dirscanner", result.base_url, run_id),
        "target": {
            "base_url": result.base_url,
        },
        "summary": {
            "outcome": "findings" if findings else "clean",
            "findings_count": len(findings),
            "highest_severity": highest_severity,
            "severity_breakdown": {k: v for k, v in severity_counts.items() if v > 0},
            "paths_scanned": result.stats.processed,
            "elapsed_seconds": round(result.elapsed, 2),
            "aborted_early": result.stats.aborted_early,
            "timeouts": result.stats.timeouts,
            "request_errors": result.stats.request_errors,
        },
        "findings": findings,
    }

    run_dir.write_json(run_dir.report_file, report)
    return report
