"""Phase A.3 — credentials subsystem tests."""

import os
import pytest

from leetha.inventory.credentials import (
    store_secret, get_secret, delete_secret,
    _KEY_FILENAME, _DB_FILENAME,
)


def test_store_and_get_roundtrip(tmp_path):
    store_secret("unifi", "hunter2", data_dir=tmp_path)
    assert get_secret("unifi", data_dir=tmp_path) == "hunter2"


def test_env_var_override_beats_stored(tmp_path, monkeypatch):
    store_secret("unifi", "from-disk", data_dir=tmp_path)
    monkeypatch.setenv("LEETHA_UNIFI_SECRET", "from-env")
    assert get_secret("unifi", data_dir=tmp_path) == "from-env"


def test_missing_returns_none(tmp_path):
    assert get_secret("never-stored", data_dir=tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="Unix file-permission bits do not apply on Windows")
def test_keyfile_chmod_is_600(tmp_path):
    store_secret("x", "y", data_dir=tmp_path)
    key_path = tmp_path / _KEY_FILENAME
    assert key_path.exists()
    mode = key_path.stat().st_mode & 0o777
    # group/other bits must be off
    assert mode & 0o077 == 0, f"key file has too-permissive mode: {oct(mode)}"


def test_tampered_ciphertext_returns_none(tmp_path):
    store_secret("foo", "bar", data_dir=tmp_path)
    # Corrupt the DB blob
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / _DB_FILENAME))
    conn.execute("UPDATE secrets SET blob = ? WHERE name = 'foo'", (b"\x00" * 32,))
    conn.commit()
    conn.close()
    assert get_secret("foo", data_dir=tmp_path) is None


def test_delete_secret(tmp_path):
    store_secret("temp", "gone", data_dir=tmp_path)
    delete_secret("temp", data_dir=tmp_path)
    assert get_secret("temp", data_dir=tmp_path) is None


def test_update_existing_secret(tmp_path):
    store_secret("k", "v1", data_dir=tmp_path)
    store_secret("k", "v2", data_dir=tmp_path)
    assert get_secret("k", data_dir=tmp_path) == "v2"


def test_same_plaintext_different_ciphertext(tmp_path):
    """Random nonces must produce different ciphertexts for the same plaintext."""
    store_secret("a", "same", data_dir=tmp_path)
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / _DB_FILENAME))
    cur = conn.execute("SELECT blob FROM secrets WHERE name = 'a'")
    blob1 = cur.fetchone()[0]
    conn.close()

    store_secret("a", "same", data_dir=tmp_path)  # same plaintext, new nonce
    conn = sqlite3.connect(str(tmp_path / _DB_FILENAME))
    cur = conn.execute("SELECT blob FROM secrets WHERE name = 'a'")
    blob2 = cur.fetchone()[0]
    conn.close()

    assert blob1 != blob2
