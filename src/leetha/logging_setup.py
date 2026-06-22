"""Centralized logging configuration for leetha.

leetha historically configured no logging handlers, so Python's
``lastResort`` handler dumped every WARNING+ record straight to stderr.
In the interactive Rich console that corrupted the display — log lines
landed on top of the REPL prompt, sometimes asynchronously from
background ``asyncio`` tasks.

:func:`setup_logging` attaches a rotating file handler to the root logger
so that:

* records are written to ``<data_dir>/leetha.log`` instead of the
  terminal, and
* ``lastResort`` never fires (the root logger now owns a handler), which
  keeps the interactive console and web UI clean.

The level is INFO by default, overridable via the ``LEETHA_LOG_LEVEL``
environment variable or an explicit ``level`` argument (e.g. from a
``--log-level`` flag). Secret-looking tokens are scrubbed via the existing
:class:`~leetha.inventory.log_filter.SecretScrubFilter` before anything is
written to disk.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False
_LOG_FILENAME = "leetha.log"
_DEFAULT_LEVEL = "INFO"
_MAX_BYTES = 5 * 1024 * 1024  # 5 MB per file
_BACKUP_COUNT = 3


def _resolve_level(level: str | int | None) -> int:
    """Resolve a log level from an explicit arg, env var, or the default."""
    raw = level if level is not None else os.environ.get("LEETHA_LOG_LEVEL")
    if raw is None or raw == "":
        raw = _DEFAULT_LEVEL
    if isinstance(raw, int):
        return raw
    resolved = logging.getLevelName(str(raw).strip().upper())
    return resolved if isinstance(resolved, int) else logging.INFO


def setup_logging(
    data_dir: Path,
    level: str | int | None = None,
    *,
    console: bool = False,
) -> Path | None:
    """Route leetha's logs to a rotating file under *data_dir*.

    Idempotent: repeated calls (e.g. after a sudo re-exec) only adjust the
    level rather than stacking handlers.

    Parameters
    ----------
    data_dir:
        Directory for the log file (``<data_dir>/leetha.log``).
    level:
        Explicit level name/number; falls back to ``LEETHA_LOG_LEVEL`` then
        INFO.
    console:
        Also mirror WARNING+ records to stderr. Off by default so the
        interactive console / web UI keep the terminal clean; useful for
        non-interactive CLI subcommands or debugging.

    Returns the log file path, or ``None`` when only a stderr handler was
    installed (file creation failed) or on an idempotent re-call. Logging
    is best-effort and never blocks startup.
    """
    global _CONFIGURED
    resolved = _resolve_level(level)
    root = logging.getLogger()

    if _CONFIGURED:
        # Already wired up (e.g. second pass after sudo re-exec) — just
        # honor any new level without duplicating handlers.
        root.setLevel(resolved)
        for h in root.handlers:
            if getattr(h, "_leetha_handler", False):
                h.setLevel(resolved)
        return None

    from leetha.inventory.log_filter import SecretScrubFilter

    root.setLevel(resolved)
    log_path: Path | None = None
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        log_path = data_dir / _LOG_FILENAME
        file_handler = RotatingFileHandler(
            log_path, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(resolved)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
        ))
        file_handler.addFilter(SecretScrubFilter())
        file_handler._leetha_handler = True  # tag for idempotent re-config
        root.addHandler(file_handler)

        # When launched via sudo, hand the log file back to the real user so
        # later non-root runs can still write to it.
        from leetha.platform import fix_ownership
        fix_ownership(log_path)
    except OSError:
        # Disk full / permission issue — fall back to a stderr handler so we
        # still capture something and lastResort stays suppressed.
        log_path = None
        console = True

    if console:
        stream = logging.StreamHandler()
        stream.setLevel(max(resolved, logging.WARNING))
        stream.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        stream.addFilter(SecretScrubFilter())
        stream._leetha_handler = True
        root.addHandler(stream)

    _CONFIGURED = True
    return log_path


def reset_logging_for_tests() -> None:
    """Remove leetha-installed handlers and reset state. Test-only."""
    global _CONFIGURED
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_leetha_handler", False):
            root.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
    _CONFIGURED = False
