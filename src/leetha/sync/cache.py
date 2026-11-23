"""Persist a feed snapshot and its freshness metadata in one atomic write."""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_SYNC_PREFIX = '{"sync":'
_MAX_HEADER = 4096


def write_feed_cache(
    path: Path, source: str, entries: dict | list, entry_count: int, etag: str | None = None,
) -> None:
    sync = {
        "last_synced_at": datetime.now(timezone.utc).isoformat(),
        "entry_count": entry_count,
        "upstream_etag": etag if etag and len(etag) <= 512 else None,
    }
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.stem}.", suffix=".tmp", delete=False,
        ) as stream:
            temp_path = Path(stream.name)
            # The first line can be read without deserializing the entries.
            stream.write(f"{_SYNC_PREFIX}{json.dumps(sync)},\n")
            stream.write(f'"source":{json.dumps(source)},"entries":')
            json.dump(entries, stream)
            stream.write("}")
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def read_feed_freshness(path: Path) -> dict | None:
    """Read just the metadata for a cache, with a file-date fallback for older caches."""
    try:
        with path.open(encoding="utf-8") as stream:
            header = stream.readline(_MAX_HEADER)
            if header.startswith(_SYNC_PREFIX) and header.endswith(",\n"):
                snapshot = json.loads(header[len(_SYNC_PREFIX):-2])
                if isinstance(snapshot, dict):
                    return snapshot
            mtime = os.fstat(stream.fileno()).st_mtime
    except (OSError, ValueError):
        return None
    return {
        "last_synced_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat(),
        "entry_count": None,
        "upstream_etag": None,
    }
