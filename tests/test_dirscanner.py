"""
Test suite for dirscanner.

Covers: URL validation, path normalisation, directory-index detection,
severity classification, run-directory management, report building, and
the CLI scan/report commands via Typer's test runner.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from dirscanner.cli.commands import app
from dirscanner.core.scanner import (
    Probe,
    ScanConfig,
    ScanResult,
    ScanStats,
    is_directory_index,
    normalize_paths,
    validate_url,
)
from dirscanner.core.severity import classify_severity
from dirscanner.output.reporter import RunDirectory, _sanitize, build_report

runner = CliRunner(mix_stderr=False)


class TestValidateUrl:
    def test_adds_http_scheme(self) -> None:
        assert validate_url("example.com").startswith("http://")

    def test_preserves_https(self) -> None:
        assert validate_url("https://example.com").startswith("https://")

    def test_strips_double_quotes(self) -> None:
        assert validate_url('"https://example.com"') == "https://example.com/"

    def test_strips_single_quotes(self) -> None:
        assert validate_url("'https://example.com'") == "https://example.com/"

    def test_rejects_ftp(self) -> None:
        assert validate_url("ftp://example.com") == ""

    def test_rejects_empty(self) -> None:
        assert validate_url("") == ""

    def test_rejects_whitespace_only(self) -> None:
        assert validate_url("   ") == ""

    def test_preserves_port(self) -> None:
        assert ":8080" in validate_url("http://example.com:8080/")

    def test_handles_path(self) -> None:
        assert "/some/path" in validate_url("https://example.com/some/path")

    def test_normalises_trailing_slash(self) -> None:
        assert validate_url("https://example.com").endswith("/")

    def test_rejects_invalid_hostname_chars(self) -> None:
        assert validate_url("http://exa mple.com") == ""


class TestNormalizePaths:
    def test_adds_trailing_slash(self) -> None:
        result = normalize_paths(["admin", "backup"])
        assert "admin/" in result
        assert "backup/" in result

    def test_deduplicates(self) -> None:
        result = normalize_paths(["admin/", "admin", "admin/"])
        assert result.count("admin/") == 1

    def test_handles_root(self) -> None:
        assert "/" in normalize_paths(["/"])

    def test_handles_dot_as_root(self) -> None:
        assert "/" in normalize_paths(["."])

    def test_skips_empty_strings(self) -> None:
        result = normalize_paths(["", "  ", "admin"])
        assert "" not in result

    def test_skips_slash_only_after_strip(self) -> None:
        normalize_paths(["///"])
        assert "/" in normalize_paths(["/"])

    def test_preserves_first_occurrence_order(self) -> None:
        result = normalize_paths(["b", "a", "b"])
        assert result.index("b/") < result.index("a/")

    def test_strips_leading_slash_from_non_root(self) -> None:
        result = normalize_paths(["/admin"])
        assert "admin/" in result
        assert "/admin/" not in result

    def test_empty_iterable(self) -> None:
        assert normalize_paths([]) == []


class TestIsDirectoryIndex:
    def _make_response(self, body: str, content_type: str = "text/html") -> MagicMock:
        resp = MagicMock()
        resp.text = body
        resp.headers = {"content-type": content_type}
        return resp

    def test_detects_index_of_in_title(self) -> None:
        assert is_directory_index(self._make_response("<title>Index of /backup</title>")) is True

    def test_detects_parent_directory(self) -> None:
        assert is_directory_index(self._make_response("Parent Directory")) is True

    def test_detects_h1_index_of(self) -> None:
        assert is_directory_index(self._make_response("<h1>Index of /uploads</h1>")) is True

    def test_detects_directory_listing_for(self) -> None:
        assert is_directory_index(self._make_response("Directory listing for /tmp")) is True

    def test_case_insensitive_detection(self) -> None:
        assert is_directory_index(self._make_response("INDEX OF /")) is True

    def test_ignores_json_content_type(self) -> None:
        assert is_directory_index(self._make_response("Index of /", "application/json")) is False

    def test_ignores_image_content_type(self) -> None:
        assert is_directory_index(self._make_response("", "image/png")) is False

    def test_normal_html_page_returns_false(self) -> None:
        assert is_directory_index(self._make_response("<html><body>Hello</body></html>")) is False

    def test_empty_content_type_falls_through(self) -> None:
        resp = MagicMock()
        resp.text = "<title>Index of /etc</title>"
        resp.headers = {}
        assert is_directory_index(resp) is True


class TestClassifySeverity:
    def test_ssh_is_critical(self) -> None:
        assert classify_severity(".ssh/") == "critical"

    def test_htpasswd_is_critical(self) -> None:
        assert classify_severity(".htpasswd") == "critical"

    def test_env_is_critical(self) -> None:
        assert classify_severity(".env") == "critical"

    def test_git_is_high(self) -> None:
        assert classify_severity(".git/") == "high"

    def test_admin_is_high(self) -> None:
        assert classify_severity("admin/") == "high"

    def test_backup_is_high(self) -> None:
        assert classify_severity("backup/") == "high"

    def test_phpmyadmin_is_high(self) -> None:
        assert classify_severity("phpmyadmin/") == "high"

    def test_uploads_is_medium(self) -> None:
        assert classify_severity("uploads/") == "medium"

    def test_tmp_is_medium(self) -> None:
        assert classify_severity("tmp/") == "medium"

    def test_api_is_medium(self) -> None:
        assert classify_severity("api/") == "medium"

    def test_images_is_low(self) -> None:
        assert classify_severity("images/") == "low"

    def test_css_is_low(self) -> None:
        assert classify_severity("css/") == "low"

    def test_vendor_is_low(self) -> None:
        assert classify_severity("vendor/") == "low"

    def test_unknown_path_is_info(self) -> None:
        assert classify_severity("completely-unknown-path-xyz/") == "info"

    def test_case_insensitive(self) -> None:
        assert classify_severity("ADMIN/") == "high"
        assert classify_severity("UPLOADS/") == "medium"

    def test_leading_slash_stripped(self) -> None:
        assert classify_severity("/admin/") == "high"


class TestScanConfig:
    def test_defaults(self) -> None:
        cfg = ScanConfig()
        assert cfg.threads == 8
        assert cfg.timeout == 7
        assert cfg.wordlist_only is False
        assert cfg.scan_base_url is True
        assert cfg.retries == 0

    def test_custom_values(self) -> None:
        cfg = ScanConfig(threads=4, timeout=15, max_paths=100)
        assert cfg.threads == 4
        assert cfg.timeout == 15
        assert cfg.max_paths == 100


@pytest.fixture
def run_dir(tmp_path: Path) -> RunDirectory:
    return RunDirectory(root=tmp_path, run_id="test-run-001")


class TestRunDirectory:
    def test_creates_subdirectories(self, run_dir: RunDirectory) -> None:
        assert run_dir.root.is_dir()
        assert run_dir.raw_req.is_dir()
        assert run_dir.raw_res.is_dir()

    def test_log_file_path_is_inside_root(self, run_dir: RunDirectory) -> None:
        assert run_dir.log_file.parent == run_dir.root

    def test_write_json(self, run_dir: RunDirectory) -> None:
        path = run_dir.root / "test.json"
        run_dir.write_json(path, {"key": "value", "num": 42})
        data = json.loads(path.read_text())
        assert data == {"key": "value", "num": 42}

    def test_write_json_handles_unicode(self, run_dir: RunDirectory) -> None:
        path = run_dir.root / "unicode.json"
        run_dir.write_json(path, {"msg": "こんにちは"})
        assert "こんにちは" in path.read_text(encoding="utf-8")

    def test_write_probe_artefacts_creates_files(self, run_dir: RunDirectory) -> None:
        probe = Probe(
            path="/admin/",
            target="http://example.com/admin/",
            user_agent="TestAgent/1.0",
            open=True,
            status_code=200,
            response_body="<title>Index of /admin/</title>",
            response_headers={"content-type": "text/html"},
        )
        req_path, res_path = run_dir.write_probe_artefacts(1, probe)
        assert req_path.exists()
        assert res_path.exists()

    def test_write_probe_artefacts_request_content(self, run_dir: RunDirectory) -> None:
        probe = Probe(
            path="/admin/",
            target="http://example.com/admin/",
            user_agent="TestAgent/1.0",
            open=True,
            status_code=200,
        )
        req_path, _ = run_dir.write_probe_artefacts(1, probe)
        data = json.loads(req_path.read_text())
        assert data["method"] == "GET"
        assert data["url"] == "http://example.com/admin/"
        assert data["headers"]["User-Agent"] == "TestAgent/1.0"

    def test_write_probe_artefacts_response_content(self, run_dir: RunDirectory) -> None:
        probe = Probe(
            path="/admin/",
            target="http://example.com/admin/",
            user_agent="TestAgent/1.0",
            open=True,
            status_code=200,
            response_body="<html>Index of /admin/</html>",
            response_headers={"content-type": "text/html"},
        )
        _, res_path = run_dir.write_probe_artefacts(1, probe)
        data = json.loads(res_path.read_text())
        assert data["status_code"] == 200
        assert "<html>" in data["body"]


class TestBuildReport:
    def test_clean_scan_outcome(self, tmp_path: Path) -> None:
        run_dir = RunDirectory(root=tmp_path, run_id="clean-run")
        result = ScanResult(
            base_url="https://example.com/",
            open_urls=[],
            probes=[],
            stats=ScanStats(processed=100),
            elapsed=5.0,
        )
        report = build_report(result, "clean-run", run_dir)
        assert report["summary"]["outcome"] == "clean"
        assert report["summary"]["findings_count"] == 0
        assert report["summary"]["highest_severity"] is None

    def test_report_json_written_to_disk(self, tmp_path: Path) -> None:
        run_dir = RunDirectory(root=tmp_path, run_id="disk-test")
        result = ScanResult(
            base_url="https://example.com/",
            open_urls=[],
            probes=[],
            stats=ScanStats(processed=10),
            elapsed=1.0,
        )
        build_report(result, "disk-test", run_dir)
        assert run_dir.report_file.exists()
        data = json.loads(run_dir.report_file.read_text())
        assert data["run_id"] == "disk-test"
        assert data["schema_version"] == "1.1"

    def test_findings_scan_severity(self, tmp_path: Path) -> None:
        run_dir = RunDirectory(root=tmp_path, run_id="findings-run")
        probe = Probe(
            path="/backup/",
            target="https://example.com/backup/",
            user_agent="TestAgent/1.0",
            open=True,
            status_code=200,
            response_body="<title>Index of /backup/</title>",
            response_headers={},
        )
        result = ScanResult(
            base_url="https://example.com/",
            open_urls=["https://example.com/backup/"],
            probes=[probe],
            stats=ScanStats(processed=50),
            elapsed=3.0,
        )
        report = build_report(result, "findings-run", run_dir)
        assert report["summary"]["outcome"] == "findings"
        assert report["summary"]["findings_count"] == 1
        assert report["summary"]["highest_severity"] == "high"
        finding = report["findings"][0]
        assert finding["url"] == "https://example.com/backup/"
        assert finding["severity"] == "high"
        assert finding["artefacts"]["request"] is not None
        assert finding["artefacts"]["response"] is not None

    def test_severity_breakdown(self, tmp_path: Path) -> None:
        run_dir = RunDirectory(root=tmp_path, run_id="breakdown-run")
        probes = [
            Probe(
                path=path,
                target=f"https://example.com{path}",
                user_agent="TestAgent/1.0",
                open=True,
                status_code=200,
                response_body="<title>Index of /</title>",
                response_headers={},
            )
            for path in [".ssh/", "admin/", "uploads/"]
        ]
        result = ScanResult(
            base_url="https://example.com/",
            open_urls=[p.target for p in probes],
            probes=probes,
            stats=ScanStats(processed=100),
            elapsed=2.0,
        )
        report = build_report(result, "breakdown-run", run_dir)
        breakdown = report["summary"]["severity_breakdown"]
        assert breakdown.get("critical", 0) == 1
        assert breakdown.get("high", 0) == 1
        assert breakdown.get("medium", 0) == 1
        assert report["summary"]["highest_severity"] == "critical"

    def test_skips_non_open_probes(self, tmp_path: Path) -> None:
        run_dir = RunDirectory(root=tmp_path, run_id="skip-run")
        probe = Probe(
            path="/admin/",
            target="https://example.com/admin/",
            user_agent="TestAgent/1.0",
            open=False,
            status_code=404,
        )
        result = ScanResult(
            base_url="https://example.com/",
            open_urls=[],
            probes=[probe],
            stats=ScanStats(processed=1),
            elapsed=0.5,
        )
        report = build_report(result, "skip-run", run_dir)
        assert report["summary"]["findings_count"] == 0

    def test_finding_has_required_fields(self, tmp_path: Path) -> None:
        run_dir = RunDirectory(root=tmp_path, run_id="fields-run")
        probe = Probe(
            path="/tmp/",
            target="https://example.com/tmp/",
            user_agent="TestAgent/1.0",
            open=True,
            status_code=200,
            response_body="<h1>Index of /tmp/</h1>",
            response_headers={},
        )
        result = ScanResult(
            base_url="https://example.com/",
            open_urls=[probe.target],
            probes=[probe],
            stats=ScanStats(processed=5),
            elapsed=1.0,
        )
        report = build_report(result, "fields-run", run_dir)
        finding = report["findings"][0]
        for field in ("instance_id", "fingerprint", "url", "path", "status_code",
                      "severity", "title", "description", "remediation", "artefacts"):
            assert field in finding, f"Missing field: {field}"


class TestSanitize:
    def test_removes_special_chars(self) -> None:
        assert _sanitize("/admin/backup/") == "admin_backup"

    def test_preserves_alphanumeric(self) -> None:
        assert _sanitize("abc123") == "abc123"

    def test_empty_string_becomes_unknown(self) -> None:
        assert _sanitize("") == "unknown"

    def test_preserves_dots_hyphens_underscores(self) -> None:
        assert _sanitize("my-file_v1.2") == "my-file_v1.2"


def _make_scan_result(
    base_url: str = "https://example.com/",
    open_urls: list[str] | None = None,
    probes: list[Probe] | None = None,
    processed: int = 10,
) -> ScanResult:
    return ScanResult(
        base_url=base_url,
        open_urls=open_urls or [],
        probes=probes or [],
        stats=ScanStats(processed=processed),
        elapsed=1.0,
    )


class TestCLIScan:
    def test_invalid_url_exits_2(self) -> None:
        result = runner.invoke(app, ["scan", "not-a-valid-!!url"])
        assert result.exit_code == 2

    def test_ftp_url_exits_2(self) -> None:
        result = runner.invoke(app, ["scan", "ftp://example.com"])
        assert result.exit_code == 2

    def test_clean_scan_exits_0(self, tmp_path: Path) -> None:
        with patch("dirscanner.cli.commands.scan", return_value=_make_scan_result()):
            result = runner.invoke(
                app,
                ["scan", "https://example.com", "--output-dir", str(tmp_path), "--no-banner"],
            )
        assert result.exit_code == 0

    def test_findings_scan_exits_1(self, tmp_path: Path) -> None:
        probe = Probe(
            path="/admin/",
            target="https://example.com/admin/",
            user_agent="TestAgent",
            open=True,
            status_code=200,
            response_body="<title>Index of /admin/</title>",
            response_headers={},
        )
        scan_result = _make_scan_result(
            open_urls=["https://example.com/admin/"],
            probes=[probe],
        )
        with patch("dirscanner.cli.commands.scan", return_value=scan_result):
            result = runner.invoke(
                app,
                ["scan", "https://example.com", "--output-dir", str(tmp_path), "--no-banner"],
            )
        assert result.exit_code == 1

    def test_quiet_mode_prints_urls_only(self, tmp_path: Path) -> None:
        probe = Probe(
            path="/admin/",
            target="https://example.com/admin/",
            user_agent="TestAgent",
            open=True,
            status_code=200,
            response_body="<title>Index of /admin/</title>",
            response_headers={},
        )
        scan_result = _make_scan_result(
            open_urls=["https://example.com/admin/"],
            probes=[probe],
        )
        with patch("dirscanner.cli.commands.scan", return_value=scan_result):
            result = runner.invoke(
                app,
                ["scan", "https://example.com", "--output-dir", str(tmp_path), "--quiet"],
            )
        assert "https://example.com/admin/" in result.output
        assert "Scanning" not in result.output

    def test_report_json_created_on_clean_scan(self, tmp_path: Path) -> None:
        with patch("dirscanner.cli.commands.scan", return_value=_make_scan_result()):
            runner.invoke(
                app,
                ["scan", "https://example.com", "--output-dir", str(tmp_path), "--no-banner"],
            )
        run_dirs = list(tmp_path.iterdir())
        assert len(run_dirs) == 1
        report_file = run_dirs[0] / "report.json"
        assert report_file.exists()
        data = json.loads(report_file.read_text())
        assert data["summary"]["outcome"] == "clean"

    def test_missing_paths_file_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "scan", "https://example.com",
                "--output-dir", str(tmp_path),
                "--paths-file", str(tmp_path / "nonexistent.txt"),
            ],
        )
        assert result.exit_code == 2

    def test_unreachable_target_exits_3(self, tmp_path: Path) -> None:
        all_failed = _make_scan_result()
        all_failed.stats.timeouts = 10
        all_failed.stats.request_errors = 0
        all_failed.stats.processed = 10
        with patch("dirscanner.cli.commands.scan", return_value=all_failed):
            result = runner.invoke(
                app,
                ["scan", "https://example.com", "--output-dir", str(tmp_path), "--no-banner"],
            )
        assert result.exit_code == 3

    def test_custom_run_id_used(self, tmp_path: Path) -> None:
        with patch("dirscanner.cli.commands.scan", return_value=_make_scan_result()):
            runner.invoke(
                app,
                [
                    "scan", "https://example.com",
                    "--output-dir", str(tmp_path),
                    "--run-id", "my-custom-run",
                    "--no-banner",
                ],
            )
        assert (tmp_path / "my-custom-run").is_dir()

    def test_invalid_threads_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["scan", "https://example.com", "--output-dir", str(tmp_path), "--threads", "0"],
        )
        assert result.exit_code == 2

    def test_invalid_timeout_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["scan", "https://example.com", "--output-dir", str(tmp_path), "--timeout", "0"],
        )
        assert result.exit_code == 2


class TestCLIReport:
    def test_missing_report_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["report", str(tmp_path / "nonexistent.json")])
        assert result.exit_code == 2

    def test_valid_report_prints_summary(self, tmp_path: Path) -> None:
        report_data = {
            "schema_version": "1.1",
            "summary": {
                "outcome": "clean",
                "findings_count": 0,
                "highest_severity": None,
                "severity_breakdown": {},
                "paths_scanned": 100,
                "elapsed_seconds": 5.0,
                "aborted_early": False,
                "timeouts": 0,
                "request_errors": 0,
            },
            "findings": [],
        }
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report_data))
        result = runner.invoke(app, ["report", str(report_file), "--no-banner"])
        assert result.exit_code == 0
        assert "Findings" in result.output

    def test_malformed_json_exits_2(self, tmp_path: Path) -> None:
        report_file = tmp_path / "bad.json"
        report_file.write_text("this is not valid JSON {{{")
        result = runner.invoke(app, ["report", str(report_file), "--no-banner"])
        assert result.exit_code == 2


class TestCLIVersion:
    def test_version_command(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "dirscanner" in result.output
