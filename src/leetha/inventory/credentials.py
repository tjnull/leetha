"""Phase A.3 — AES-GCM credential store with env-var override.

Design:
- Secrets are stored in ``<data_dir>/secrets.db`` (sqlite, one row per importer).
- A single 256-bit master key lives at ``<data_dir>/secrets.key`` (chmod 600).
- Ciphertext is ``nonce (12 bytes) || ciphertext || tag (16 bytes)``.
- Callers can override any secret at read time via ``LEETHA_<NAME>_SECRET``
  environment variables — useful for CI, tests, and container deployments.

Module-level ``get_secret`` / ``store_secret`` / ``delete_secret`` default to
``config.data_dir``. Tests can pass an explicit ``data_dir`` to avoid touching
the real config directory.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_KEY_FILENAME = "secrets.key"
_DB_FILENAME = "secrets.db"
_NONCE_SIZE = 12  # 96 bits for AES-GCM


def _default_data_dir() -> Path:
    from leetha.config import get_config
    return Path(get_config().data_dir)


def _resolve_dir(data_dir: Path | str | None) -> Path:
    return Path(data_dir) if data_dir is not None else _default_data_dir()


def _load_or_create_key(data_dir: Path) -> bytes:
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / _KEY_FILENAME
    if key_path.exists():
        return key_path.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    key_path.write_bytes(key)
    try:
        key_path.chmod(0o600)
    except PermissionError:
        pass
    return key


def _connect(data_dir: Path) -> sqlite3.Connection:
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / _DB_FILENAME
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, blob BLOB NOT NULL)"
    )
    conn.commit()
    return conn


def store_secret(name: str, plaintext: str, *, data_dir: Path | str | None = None) -> None:
    """Encrypt and persist a secret for the given importer/channel name."""
    d = _resolve_dir(data_dir)
    key = _load_or_create_key(d)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ciphertext = aes.encrypt(nonce, plaintext.encode("utf-8"), associated_data=name.encode("utf-8"))
    blob = nonce + ciphertext
    conn = _connect(d)
    try:
        conn.execute(
            "INSERT INTO secrets (name, blob) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET blob = excluded.blob",
            (name, blob),
        )
        conn.commit()
    finally:
        conn.close()


def get_secret(name: str, *, data_dir: Path | str | None = None) -> str | None:
    """Return the plaintext secret; env-var override takes priority."""
    env_key = f"LEETHA_{name.upper()}_SECRET"
    env_val = os.environ.get(env_key)
    if env_val is not None:
        return env_val

    d = _resolve_dir(data_dir)
    key_path = d / _KEY_FILENAME
    db_path = d / _DB_FILENAME
    if not key_path.exists() or not db_path.exists():
        return None
    key = key_path.read_bytes()
    conn = _connect(d)
    try:
        cur = conn.execute("SELECT blob FROM secrets WHERE name = ?", (name,))
        row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    blob = row[0]
    if len(blob) < _NONCE_SIZE + 16:
        return None
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data=name.encode("utf-8"))
    except Exception:
        return None
    return plaintext.decode("utf-8")


def delete_secret(name: str, *, data_dir: Path | str | None = None) -> None:
    d = _resolve_dir(data_dir)
    db_path = d / _DB_FILENAME
    if not db_path.exists():
        return
    conn = _connect(d)
    try:
        conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
        conn.commit()
    finally:
        conn.close()
