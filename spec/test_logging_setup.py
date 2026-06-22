"""Logging is routed to a file so it never corrupts the interactive console.

leetha configured no logging handlers, so Python's lastResort handler sent
every WARNING+ record to stderr — landing on top of the Rich REPL prompt
(notably the async "sensor listener disabled" line). setup_logging() must
attach a file handler to the root logger so lastResort is suppressed and
records go to <data_dir>/leetha.log instead of the terminal.
"""

from __future__ import annotations

import logging

import pytest

from leetha.logging_setup import setup_logging, reset_logging_for_tests


@pytest.fixture(autouse=True)
def _clean_logging():
    reset_logging_for_tests()
    yield
    reset_logging_for_tests()


def test_records_go_to_logfile_not_stderr(tmp_path, capsys):
    log_path = setup_logging(tmp_path, level="INFO")
    assert log_path == tmp_path / "leetha.log"

    log = logging.getLogger("leetha.capture.remote.listener")
    log.info("sensor listener disabled — no CA yet")
    log.warning("something noteworthy")
    logging.shutdown()

    contents = log_path.read_text()
    assert "sensor listener disabled" in contents
    assert "something noteworthy" in contents

    # Nothing leaked to the terminal.
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_root_handler_suppresses_lastresort(tmp_path):
    setup_logging(tmp_path, level="WARNING")
    root = logging.getLogger()
    assert any(getattr(h, "_leetha_handler", False) for h in root.handlers)
    # A configured root handler is exactly what stops logging.lastResort.


def test_secrets_are_scrubbed(tmp_path):
    log_path = setup_logging(tmp_path, level="INFO")
    logging.getLogger("leetha.test").warning("auth token=hunter2 leaked")
    logging.shutdown()
    contents = log_path.read_text()
    assert "hunter2" not in contents
    assert "[REDACTED]" in contents


def test_level_resolves_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LEETHA_LOG_LEVEL", "ERROR")
    setup_logging(tmp_path)
    assert logging.getLogger().level == logging.ERROR


def test_explicit_level_overrides_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LEETHA_LOG_LEVEL", "ERROR")
    setup_logging(tmp_path, level="DEBUG")
    assert logging.getLogger().level == logging.DEBUG


def test_idempotent_no_duplicate_handlers(tmp_path):
    setup_logging(tmp_path, level="INFO")
    n_first = len(logging.getLogger().handlers)
    # A second call (e.g. after a sudo re-exec) must not stack handlers.
    setup_logging(tmp_path, level="WARNING")
    root = logging.getLogger()
    assert len(root.handlers) == n_first
    # ...but it still honors the new level.
    assert root.level == logging.WARNING


def test_console_mirror_adds_stderr_handler(tmp_path, capsys):
    setup_logging(tmp_path, level="INFO", console=True)
    logging.getLogger("leetha.test").warning("visible on stderr")
    logging.shutdown()
    captured = capsys.readouterr()
    assert "visible on stderr" in captured.err


def test_bad_level_falls_back_to_info(tmp_path):
    setup_logging(tmp_path, level="NOPE")
    assert logging.getLogger().level == logging.INFO
