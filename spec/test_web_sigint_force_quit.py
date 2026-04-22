"""Web-mode SIGINT: first press triggers graceful uvicorn shutdown,
second press (or beyond) force-exits via ``os._exit(0)``.

User symptom: Ctrl+C inside ``web`` sub-mode printed uvicorn's
"Waiting for connections to close. (CTRL+C to force quit)" — but
subsequent Ctrl+C presses did nothing, because our custom
``_web_sigint`` handler intercepted them and only re-set the
``should_exit`` flag that was already True. Active websocket
connections kept uvicorn hung.

Source-level pin: the handler must bump a counter / flag on each
call and hard-exit on the second invocation, matching uvicorn's
native two-press semantics.
"""

from pathlib import Path


SRC = (Path(__file__).resolve().parents[1] / "src" / "leetha" / "console.py").read_text()


def _web_sigint_block() -> str:
    """Extract the ``_web_sigint`` function body + its enclosing closure setup."""
    idx = SRC.find("def _web_sigint(")
    assert idx >= 0, "console.py must define _web_sigint"
    # Look for the end of the handler — its caller uses ``signal.signal(SIGINT, _web_sigint)``.
    end = SRC.find("signal.signal(signal.SIGINT, _web_sigint)", idx)
    assert end > idx
    return SRC[idx:end]


def test_web_sigint_has_force_exit_escape():
    block = _web_sigint_block()
    assert "os._exit(" in block, (
        "_web_sigint must force-exit on repeated Ctrl+C so uvicorn's "
        "'Waiting for connections to close' can't hang indefinitely. "
        f"current handler body: {block!r}"
    )


def test_web_sigint_tracks_press_count():
    """Handler must detect repeat presses — either a counter or an
    already-called flag — so the first press is graceful and the second
    is a hard exit."""
    block = _web_sigint_block()
    # Look for any mutable tracker: list append, nonlocal int, attribute, etc.
    has_counter = any(token in block for token in (
        "nonlocal _web_sigint_count",
        "_web_sigint_count",
        "_sigint_count",
        ".append(",
        "_force_quit",
    ))
    assert has_counter, (
        "_web_sigint needs to know whether this is the first or subsequent "
        f"Ctrl+C press. Handler body: {block!r}"
    )
