"""Phase A.3 — log scrubber tests."""

import logging
import pytest

from leetha.inventory.log_filter import SecretScrubFilter, _scrub, install_scrubber


@pytest.mark.parametrize("raw,expected_pattern", [
    ("Authorization: Bearer abc.def.ghi", "Bearer"),
    ("GET /api?token=hunter2", "token="),
    ("login: password=hunter2", "password="),
    ("Cookie: JSESSIONID=ABCDEF1234", "JSESSIONID="),
    ('Digest response="deadbeefdeadbeef"', 'response="'),
    ('{"api_key": "s3cr3t"}', "api_key"),
])
def test_scrub_redacts_pattern(raw, expected_pattern):
    scrubbed = _scrub(raw)
    assert "[REDACTED]" in scrubbed
    assert "hunter2" not in scrubbed
    assert "abc.def.ghi" not in scrubbed
    assert "ABCDEF1234" not in scrubbed
    assert "deadbeef" not in scrubbed
    assert "s3cr3t" not in scrubbed


def test_scrub_preserves_normal_text():
    raw = "Importer ran successfully with 42 devices"
    assert _scrub(raw) == raw


def test_filter_on_logger(caplog):
    logger = logging.getLogger("leetha.inventory.test_logfilter")
    logger.addFilter(SecretScrubFilter())
    with caplog.at_level(logging.INFO, logger=logger.name):
        logger.info("calling %s", "Bearer secret-token-123")
    assert any("[REDACTED]" in r.getMessage() for r in caplog.records)
    assert not any("secret-token-123" in r.getMessage() for r in caplog.records)


def test_install_scrubber_attaches_filter():
    logger = logging.getLogger("leetha.inventory")
    # Remove existing filters to get a clean count
    install_scrubber()
    assert any(isinstance(f, SecretScrubFilter) for f in logger.filters)
