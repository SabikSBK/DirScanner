"""
Core directory scanner engine.

Scans a target URL for open directory listings using a built-in wordlist
and optional user-supplied paths. Entirely self-contained — no external
services or optional dependencies required.
"""

import logging
import random
import re
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .directorylist import DIRECTORIES

logger = logging.getLogger("dirscanner")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """All tunable parameters for a single scan run.

    Attributes:
        threads: Number of concurrent HTTP workers.
        timeout: Per-request timeout in seconds.
        min_delay: Minimum random inter-request delay (seconds).
        max_delay: Maximum random inter-request delay (seconds).
        retries: Extra retry attempts per request on failure (0 = no retries).
        wordlist_only: When True, use *only* the built-in wordlist, ignoring
            any extra paths supplied by the caller.  When False (default),
            merge the built-in wordlist with extra paths.
        max_paths: Hard cap on the number of paths probed. 0 = no cap.
        batch_size: Paths submitted to the thread pool in one chunk. Controls
            granularity of the cooldown and abort checks.
        cooldown_threshold: Timeout ratio within a batch that triggers a
            brief sleep between batches.
        cooldown_seconds: Duration of the inter-batch sleep.
        abort_on_sustained_timeouts: Halt the scan after several consecutive
            high-timeout batches (protects against dead targets).
        sustained_timeout_batches: Consecutive high-timeout batches required
            before the abort triggers.
        abort_timeout_ratio: Per-batch timeout ratio that counts as "high".
        abort_min_samples: Minimum probes processed before the abort can fire.
        scan_base_url: Whether to probe the root ``/`` path in addition to
            the wordlist entries.
    """

    threads: int = 8
    timeout: int = 7
    min_delay: float = 0.1
    max_delay: float = 0.4
    retries: int = 0
    wordlist_only: bool = False
    max_paths: int = 0
    batch_size: int = 250
    cooldown_threshold: float = 0.60
    cooldown_seconds: float = 2.0
    abort_on_sustained_timeouts: bool = True
    sustained_timeout_batches: int = 3
    abort_timeout_ratio: float = 0.95
    abort_min_samples: int = 300
    scan_base_url: bool = True


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class Probe:
    """Record of a single HTTP probe attempt."""

    path: str
    target: str
    user_agent: str
    open: bool = False
    status_code: int | None = None
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    error_type: str | None = None  # "timeout" | "request_error"


@dataclass
class ScanStats:
    """Aggregate counters for a completed scan."""

    processed: int = 0
    timeouts: int = 0
    request_errors: int = 0
    aborted_early: bool = False

    @property
    def failures(self) -> int:
        """Total number of failed probes (timeouts + request errors)."""
        return self.timeouts + self.request_errors


@dataclass
class ScanResult:
    """Complete output of a scan run."""

    base_url: str
    open_urls: list[str]
    probes: list[Probe]
    stats: ScanStats
    elapsed: float


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_USER_AGENTS: list[str] = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    ),
]

_DIRECTORY_INDEX_INDICATORS: list[str] = [
    "index of /",
    "parent directory",
    "<title>index of",
    "directory listing for",
    "<h1>index of",
]

# Maximum response body kept in memory per probe (bytes read from .text).
_MAX_BODY_CHARS = 20_000
# How much of the body to scan for directory-index indicators.
_DETECTION_SCAN_CHARS = 5_000


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def validate_url(url: str) -> str:
    """Validate and normalise a URL string.

    Adds an ``http://`` scheme if none is present.  Returns an empty string
    when the input cannot be turned into a valid HTTP/HTTPS URL.

    Args:
        url: Raw URL from user input.

    Returns:
        Normalised URL string, or ``""`` on validation failure.
    """
    try:
        cleaned = str(url or "").strip().strip("\"'")
        if not cleaned:
            return ""

        if not urlparse(cleaned).scheme:
            cleaned = "http://" + cleaned

        parsed = urlparse(cleaned)

        if parsed.scheme not in ("http", "https"):
            return ""

        hostname = parsed.hostname or ""
        if not hostname:
            return ""

        if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):
            return ""

        netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
        path = parsed.path or "/"
        return f"{parsed.scheme}://{netloc}{path}"

    except Exception as exc:  # pragma: no cover
        logger.debug("URL validation failed: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


def _build_headers(user_agent: str) -> dict[str, str]:
    """Return request headers including a randomised X-Forwarded-For value."""
    spoofed_ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
    return {
        "User-Agent": user_agent,
        "X-Forwarded-For": spoofed_ip,
        "X-Originating-IP": spoofed_ip,
        "X-Remote-IP": spoofed_ip,
        "X-Remote-Addr": spoofed_ip,
        "X-Client-IP": spoofed_ip,
        "X-Host": "127.0.0.1",
        "X-Forwarded-Host": "127.0.0.1",
    }


def _send_request(
    url: str,
    user_agent: str,
    timeout: int,
    retries: int,
) -> httpx.Response:
    """Send an HTTP GET, retrying up to *retries* times on failure.

    Args:
        url: Fully-qualified URL to fetch.
        user_agent: User-Agent header value.
        timeout: Request timeout in seconds.
        retries: Number of *additional* attempts after the first failure.

    Returns:
        The first successful :class:`httpx.Response`.

    Raises:
        Exception: The exception from the final failed attempt.
    """
    headers = _build_headers(user_agent)
    last_exc: Exception | None = None

    for _ in range(retries + 1):
        try:
            return httpx.get(
                url,
                headers=headers,
                timeout=timeout,
                follow_redirects=True,
            )
        except Exception as exc:
            last_exc = exc

    raise last_exc or RuntimeError("Unknown request failure")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def is_directory_index(response: httpx.Response) -> bool:
    """Return ``True`` if *response* looks like an open directory listing.

    Checks the Content-Type header and the first few kilobytes of the body
    for well-known directory-index phrases.

    Args:
        response: A completed :class:`httpx.Response` with status 200.

    Returns:
        ``True`` when the response resembles a directory index page.
    """
    content_type = str(response.headers.get("content-type", "")).lower()
    if content_type and "text/html" not in content_type:
        return False

    snippet = response.text[:_DETECTION_SCAN_CHARS].lower()
    return any(indicator in snippet for indicator in _DIRECTORY_INDEX_INDICATORS)


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------


def normalize_paths(paths: Iterable[str]) -> list[str]:
    """Deduplicate and normalise an iterable of URL path strings.

    Each path is stripped of surrounding whitespace, then formatted as
    ``<name>/`` (trailing slash added, leading slash removed, except for the
    root ``/`` which is kept as-is).  Duplicates are removed while preserving
    first-occurrence order.

    Args:
        paths: Raw path strings from the user or wordlist.

    Returns:
        Ordered list of unique normalised path strings.
    """
    normalised: list[str] = []
    seen: set[str] = set()

    for raw in paths:
        value = str(raw or "").strip()
        if not value:
            continue

        if value in ("/", "."):
            candidate = "/"
        else:
            trimmed = value.strip("/")
            if not trimmed:
                continue
            candidate = f"{trimmed}/"

        if candidate not in seen:
            seen.add(candidate)
            normalised.append(candidate)

    return normalised


# ---------------------------------------------------------------------------
# Single-path probe
# ---------------------------------------------------------------------------


def _check_directory(base_url: str, directory: str, cfg: ScanConfig) -> Probe:
    """Probe one *directory* path under *base_url* and return a :class:`Probe`.

    Applies a per-request random delay drawn from
    ``[cfg.min_delay, cfg.max_delay]``.
    """
    target = base_url if directory == "/" else urljoin(base_url, directory.rstrip("/") + "/")
    user_agent = random.choice(_USER_AGENTS)

    time.sleep(random.uniform(cfg.min_delay, cfg.max_delay))

    probe = Probe(path=directory, target=target, user_agent=user_agent)

    try:
        response = _send_request(target, user_agent, cfg.timeout, cfg.retries)
        probe.status_code = response.status_code
        probe.response_headers = dict(response.headers)

        if probe.status_code == 200 and is_directory_index(response):
            probe.open = True
            probe.response_body = response.text[:_MAX_BODY_CHARS]
            logger.info("[OPEN] %s", target)
        else:
            logger.debug("[%s] %s", probe.status_code, target)

    except Exception as exc:
        probe.error = str(exc)
        exc_name = type(exc).__name__.lower()
        exc_msg = str(exc).lower()
        probe.error_type = (
            "timeout"
            if "timed out" in exc_msg or "timeout" in exc_name
            else "request_error"
        )
        logger.debug("[FAILED] %s (%s)", target, exc)

    return probe


# ---------------------------------------------------------------------------
# Scan orchestrator
# ---------------------------------------------------------------------------


def scan(
    base_url: str,
    cfg: ScanConfig | None = None,
    extra_paths: Iterable[str] | None = None,
    progress_callback: Callable[[int, int, int], None] | None = None,
) -> ScanResult:
    """Scan *base_url* for open directory listings.

    Builds the full path list (wordlist ± extra paths), distributes work
    across a thread pool in batches, applies cooldown/abort logic on high
    timeout rates, and returns a :class:`ScanResult` with every finding.

    Args:
        base_url: Target URL.  A scheme is added if missing.
        cfg: Scan configuration; :class:`ScanConfig` defaults are used when
            ``None`` is supplied.
        extra_paths: Additional paths to probe.  Merged with the built-in
            wordlist unless ``cfg.wordlist_only`` is ``True``.
        progress_callback: Optional ``fn(processed, total, found)`` called
            after each probe completes (from worker threads — must be
            thread-safe).

    Returns:
        :class:`ScanResult` containing all open :class:`Probe` instances and
        aggregate :class:`ScanStats`.
    """
    cfg = cfg or ScanConfig()
    start_time = time.time()

    extras = normalize_paths(extra_paths or [])

    if cfg.wordlist_only:
        directories: list[str] = list(DIRECTORIES)
    elif extras:
        seen_extras = set(extras)
        base_list = [p for p in DIRECTORIES if p not in seen_extras]
        directories = extras + base_list
    else:
        directories = list(DIRECTORIES)

    if cfg.max_paths > 0:
        directories = directories[: cfg.max_paths]

    if cfg.scan_base_url and "/" not in directories:
        directories = ["/"] + directories

    total = len(directories)
    logger.info(
        "[SCAN START] %s | threads=%d | paths=%d",
        base_url,
        cfg.threads,
        total,
    )

    stats = ScanStats()
    open_probes: list[Probe] = []
    sustained_high_timeout_batches = 0
    effective_batch = max(1, cfg.batch_size)

    with ThreadPoolExecutor(max_workers=cfg.threads) as executor:
        for offset in range(0, total, effective_batch):
            batch = directories[offset : offset + effective_batch]
            futures = {
                executor.submit(_check_directory, base_url, path, cfg): path
                for path in batch
            }

            batch_timeout_count = 0

            for future in as_completed(futures):
                probe = future.result()
                stats.processed += 1

                if probe.open:
                    open_probes.append(probe)
                elif probe.error_type == "timeout":
                    stats.timeouts += 1
                    batch_timeout_count += 1
                elif probe.error_type:
                    stats.request_errors += 1

                if progress_callback:
                    progress_callback(stats.processed, total, len(open_probes))

            batch_len = len(batch)
            batch_timeout_ratio = batch_timeout_count / batch_len

            if batch_timeout_ratio >= cfg.cooldown_threshold:
                logger.info(
                    "[SCAN BACKOFF] High timeout ratio (%d/%d). Cooling down %.1fs.",
                    batch_timeout_count,
                    batch_len,
                    cfg.cooldown_seconds,
                )
                time.sleep(max(0.0, cfg.cooldown_seconds))

            if batch_timeout_ratio >= cfg.abort_timeout_ratio:
                sustained_high_timeout_batches += 1
            else:
                sustained_high_timeout_batches = 0

            if (
                cfg.abort_on_sustained_timeouts
                and stats.processed >= cfg.abort_min_samples
                and sustained_high_timeout_batches >= max(1, cfg.sustained_timeout_batches)
            ):
                logger.warning(
                    "[SCAN EARLY STOP] Sustained timeouts after %d probes.",
                    stats.processed,
                )
                stats.aborted_early = True
                break

    elapsed = time.time() - start_time
    logger.info(
        "[SCAN COMPLETE] %s | found=%d | elapsed=%.2fs",
        base_url,
        len(open_probes),
        elapsed,
    )

    return ScanResult(
        base_url=base_url,
        open_urls=[p.target for p in open_probes],
        probes=open_probes,
        stats=stats,
        elapsed=elapsed,
    )
