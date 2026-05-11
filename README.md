# DirScanner

**Directory Listing Enabled Endpoint Detection**

A standalone, local-only CLI tool that probes a target URL for exposed
directory indexes.  No external services, no accounts, no optional extras —
install and run.

---

## Features

- Probes thousands of common paths using a built-in wordlist
- Detects open directory listings via HTTP response analysis
- Severity classification (Critical → Info) based on path sensitivity
- Rich progress bar and colour-coded findings table
- Structured JSON report + raw request/response artefacts saved locally
- Configurable threads, timeouts, delays, and custom wordlists
- Graceful handling of timeouts, network failures, and unreachable targets
- Clean exit codes suitable for CI pipelines

---

## Installation

```bash
pip install dirscanner
```

Or install from source:

```bash
git clone https://github.com/SabikSBK/DirScanner
cd dirscanner
pip install .
```

**Requirements:** Python 3.11+ and no external services.

---

## Quick Start

```bash
# Scan with defaults (8 threads, built-in wordlist)
python -m dirscanner scan https://example.com

# Or using the installed entry point
dirscanner scan https://example.com
```

---

## Usage

```
dirscanner scan <URL> [OPTIONS]
```

### Scan options

| Option | Default | Description |
|---|---|---|
| `--output-dir` / `-o` | `./dirscanner-output` | Root directory for all output |
| `--run-id` | random UUID | Custom run identifier |
| `--threads` / `-t` | `8` | Concurrent HTTP workers |
| `--timeout` | `7` | Request timeout in seconds |
| `--retries` | `0` | Retry count per request |
| `--max-paths` | `0` (all) | Hard cap on paths probed |
| `--delay-min` | `0.1` | Minimum per-request delay (seconds) |
| `--delay-max` | `0.4` | Maximum per-request delay (seconds) |
| `--path` / `-p` | — | Extra path(s) to probe (repeatable) |
| `--paths-file` | — | File of paths, one per line |
| `--wordlist-only` | false | Ignore user-supplied paths; use only the built-in wordlist |
| `--no-base-url` | false | Skip probing the root `/` path |
| `--verbose` / `-v` | false | Stream debug logs to stderr |
| `--quiet` / `-q` | false | Print open URLs only (no progress bar) |
| `--no-banner` | false | Suppress the ASCII banner |

### Examples

```bash
# Increase threads and timeout
dirscanner scan https://example.com --threads 16 --timeout 15

# Add custom paths on top of the wordlist
dirscanner scan https://example.com -p /internal/ -p /staging/

# Supply a custom wordlist file
dirscanner scan https://example.com --paths-file my-wordlist.txt

# Scan quietly — useful in scripts
dirscanner scan https://example.com --quiet

# Cap to the first 500 paths (fast sanity check)
dirscanner scan https://example.com --max-paths 500
```

### Reviewing a previous scan

```bash
dirscanner report ./dirscanner-output/<run-id>/report.json
```

---

## Output

Each scan creates a run directory:

```
dirscanner-output/
└── <run-id>/
    ├── report.json       ← structured findings (machine-readable)
    ├── dirscanner.log    ← full debug log
    ├── raw_req/          ← per-finding HTTP request JSON
    └── raw_res/          ← per-finding HTTP response JSON
```

### report.json schema (v1.1)

```json
{
  "schema_version": "1.1",
  "tool": "dirscanner",
  "run_id": "...",
  "timestamp": "2025-01-01T00:00:00+00:00",
  "target": { "base_url": "https://example.com/" },
  "summary": {
    "outcome": "findings",
    "findings_count": 2,
    "highest_severity": "high",
    "severity_breakdown": { "high": 1, "medium": 1 },
    "paths_scanned": 1500,
    "elapsed_seconds": 42.3,
    "aborted_early": false,
    "timeouts": 3,
    "request_errors": 0
  },
  "findings": [
    {
      "instance_id": "...",
      "fingerprint": "...",
      "url": "https://example.com/backup/",
      "path": "/backup/",
      "status_code": 200,
      "severity": "high",
      "title": "Directory Listing Enabled",
      "description": "...",
      "remediation": "...",
      "artefacts": {
        "request": "raw_req/0001-backup.json",
        "response": "raw_res/0001-backup.json"
      }
    }
  ]
}
```

---

## Severity Levels

| Level | Examples |
|---|---|
| **Critical** | `.ssh/`, `.htpasswd`, `.env`, private keys, credentials |
| **High** | `.git/`, admin panels, backup archives, config dirs, SQL dumps |
| **Medium** | `uploads/`, `tmp/`, `cache/`, `api/`, `test/`, `debug/` |
| **Low** | `images/`, `css/`, `js/`, `fonts/`, `static/`, `vendor/` |
| **Info** | Everything else |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan complete — no findings |
| `1` | Scan complete — findings detected |
| `2` | Fatal error (bad URL, missing file, filesystem issue) |
| `3` | Target unreachable (all probes failed) |

---

## Development

```bash
pip install -e ".[dev]"

# Run tests
pytest

# Type check
mypy dirscanner

# Lint
ruff check dirscanner tests
```

---

## License

MIT — see [LICENSE](LICENSE).
