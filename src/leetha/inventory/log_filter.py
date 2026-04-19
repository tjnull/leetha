"""Phase A.3 Task 21 — logging.Filter that scrubs common secret patterns."""

from __future__ import annotations

import logging
import re


_REDACTION = "[REDACTED]"

_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"token=\S+", re.IGNORECASE),
    re.compile(r"password=\S+", re.IGNORECASE),
    re.compile(r"passwd=\S+", re.IGNORECASE),
    re.compile(r"JSESSIONID=[A-Za-z0-9]+"),
    re.compile(r"Cookie:\s*[^\r\n]+", re.IGNORECASE),
    # HTTP Digest response hash
    re.compile(r'response="[a-f0-9]+"', re.IGNORECASE),
    # "apikey": "..." / api_key: ...
    re.compile(r'"api[_-]?key"\s*:\s*"[^"]*"', re.IGNORECASE),
    re.compile(r'apikey=\S+', re.IGNORECASE),
)


def _scrub(message: str) -> str:
    out = message
    for pat in _PATTERNS:
        out = pat.sub(_REDACTION, out)
    return out


class SecretScrubFilter(logging.Filter):
    """Redacts matching patterns from the final formatted message."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Scrub the rendered message once.
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        scrubbed = _scrub(rendered)
        if scrubbed != rendered:
            record.msg = scrubbed
            record.args = ()  # args already interpolated into msg
        return True


def install_scrubber(logger_name: str = "leetha.inventory") -> None:
    """Attach a SecretScrubFilter to all loggers under ``logger_name``."""
    filt = SecretScrubFilter()
    logger = logging.getLogger(logger_name)
    # Add the filter to the named logger and its children dynamically.
    logger.addFilter(filt)
    # Existing children will propagate to this logger; future loggers too.
