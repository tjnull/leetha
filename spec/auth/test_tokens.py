"""Tests for auth token generation and validation."""
import os
from pathlib import Path
from leetha.auth.tokens import generate_token, hash_token, TOKEN_PREFIX, save_admin_token, load_admin_token


def test_generate_token_has_prefix():
    token = generate_token()
    assert token.startswith(TOKEN_PREFIX)


def test_generate_token_length():
    token = generate_token()
    # ltk_ (4 chars) + 48 hex chars = 52
    assert len(token) == 52


def test_generate_token_unique():
    t1 = generate_token()
    t2 = generate_token()
    assert t1 != t2


def test_hash_token_deterministic():
    token = "ltk_aabbccdd" * 4  # fake token
    h1 = hash_token(token)
    h2 = hash_token(token)
    assert h1 == h2


def test_hash_token_is_hex_sha256():
    token = generate_token()
    h = hash_token(token)
    assert len(h) == 64  # SHA-256 hex digest
    int(h, 16)  # must be valid hex


def test_save_and_load_admin_token(tmp_path):
    token = "ltk_" + "aa" * 24
    leetha_dir = tmp_path / ".leetha"
    save_admin_token(token, leetha_dir)

    token_file = leetha_dir / "admin-token"
    assert token_file.exists()
    assert token_file.read_text(encoding="utf-8").strip() == token

    # File permissions: owner read/write only (0600) — Unix only
    import platform
    if platform.system() != "Windows":
        mode = oct(token_file.stat().st_mode & 0o777)
        assert mode == "0o600"

        # Directory permissions: owner only (0700)
        dir_mode = oct(leetha_dir.stat().st_mode & 0o777)
        assert dir_mode == "0o700"


def test_load_admin_token(tmp_path):
    token = "ltk_" + "bb" * 24
    leetha_dir = tmp_path / ".leetha"
    save_admin_token(token, leetha_dir)
    loaded = load_admin_token(leetha_dir)
    assert loaded == token


def test_load_admin_token_missing(tmp_path):
    leetha_dir = tmp_path / ".leetha"
    loaded = load_admin_token(leetha_dir)
    assert loaded is None
