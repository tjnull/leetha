"""Async HTTP retrieval utilities for the sync subsystem.

Provides coroutines for fetching single and multi-file feeds with
optional progress reporting via async generators.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

import aiohttp

log = logging.getLogger(__name__)

_REQUEST_HEADERS = {
    "User-Agent": "leetha/0.1 (network fingerprint toolkit)",
}

CHUNK_SIZE = 64 * 1024  # 64 KiB read granularity


# ===================================================================
# Single-URL retrieval
# ===================================================================

async def fetch_feed(
    url: str,
    timeout_sec: int = 120,
    extra_headers: dict | None = None,
) -> bytes | None:
    """Retrieve a single URL and return its raw bytes, or *None* on error."""
    merged_hdrs = {**_REQUEST_HEADERS, **(extra_headers or {})}
    try:
        async with aiohttp.ClientSession() as sess:
            tmo = aiohttp.ClientTimeout(total=timeout_sec)
            async with sess.get(url, timeout=tmo, headers=merged_hdrs) as resp:
                resp.raise_for_status()
                return await resp.read()
    except Exception as exc:
        log.error("Fetch failed for %s: %s", url, exc)
        return None


async def fetch_with_updates(
    url: str,
    timeout_sec: int = 120,
    extra_headers: dict | None = None,
    dest_file=None,
) -> AsyncGenerator[dict, None]:
    """Fetch a URL while yielding progress dicts as data arrives.

    If *dest_file* is an open file object, data is streamed directly to
    disk instead of accumulated in memory.  The ``"done"`` event will
    have ``"data": None`` in that case.

    Yielded dicts follow one of these shapes:
        ``{"stage": "connecting"}``
        ``{"stage": "downloading", "downloaded": N, "total": T_or_None}``
        ``{"stage": "done", "downloaded": N, "total": T, "data": <bytes|None>, "etag": <str|None>}``
        ``{"stage": "error", "error": "message"}``
    """
    merged_hdrs = {**_REQUEST_HEADERS, **(extra_headers or {})}
    try:
        async with aiohttp.ClientSession() as sess:
            yield {"stage": "connecting"}
            tmo = aiohttp.ClientTimeout(total=timeout_sec)
            async with sess.get(url, timeout=tmo, headers=merged_hdrs) as resp:
                resp.raise_for_status()
                content_len = resp.content_length
                received = 0

                yield {"stage": "downloading", "downloaded": 0, "total": content_len}

                if dest_file is not None:
                    async for piece in resp.content.iter_chunked(CHUNK_SIZE):
                        dest_file.write(piece)
                        received += len(piece)
                        yield {"stage": "downloading", "downloaded": received, "total": content_len}
                    payload = None
                else:
                    parts: list[bytes] = []
                    async for piece in resp.content.iter_chunked(CHUNK_SIZE):
                        parts.append(piece)
                        received += len(piece)
                        yield {"stage": "downloading", "downloaded": received, "total": content_len}
                    payload = b"".join(parts)

                yield {
                    "stage": "done",
                    "downloaded": received,
                    "total": content_len or received,
                    "data": payload,
                    "etag": resp.headers.get("ETag"),
                }
    except Exception as exc:
        log.error("Fetch failed for %s: %s", url, exc)
        yield {"stage": "error", "error": str(exc)}


async def fetch_feed_text(
    url: str,
    timeout_sec: int = 120,
    extra_headers: dict | None = None,
) -> str | None:
    """Retrieve a URL and decode its body as UTF-8 text, or *None* on error."""
    raw = await fetch_feed(url, timeout_sec=timeout_sec, extra_headers=extra_headers)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="ignore")


# ===================================================================
# Multi-file retrieval
# ===================================================================

async def fetch_feed_batch(
    base_url: str,
    file_list: list[str],
    timeout_sec: int = 600,
    extra_headers: dict | None = None,
) -> dict[str, bytes]:
    """Download several files under a common base URL.

    Returns ``{filename: raw_bytes}`` for every file that succeeded.
    """
    merged_hdrs = {**_REQUEST_HEADERS, **(extra_headers or {})}
    collected: dict[str, bytes] = {}
    conn = aiohttp.TCPConnector(limit=5, limit_per_host=2)
    try:
        async with aiohttp.ClientSession(connector=conn) as sess:
            tmo = aiohttp.ClientTimeout(total=timeout_sec)
            for fname in file_list:
                target = f"{base_url}{fname}"
                try:
                    async with sess.get(target, timeout=tmo, headers=merged_hdrs) as resp:
                        resp.raise_for_status()
                        collected[fname] = await resp.read()
                except Exception as exc:
                    log.warning("Failed to fetch %s: %s", fname, exc)
    except Exception as exc:
        log.error("Batch fetch session error: %s", exc)
    return collected


async def fetch_feed_batch_with_updates(
    base_url: str,
    file_list: list[str],
    timeout_sec: int = 600,
    extra_headers: dict | None = None,
) -> AsyncGenerator[dict, None]:
    """Download multiple files, yielding per-file progress events.

    Yielded dicts follow one of these shapes:
        ``{"stage": "connecting"}``
        ``{"stage": "downloading", "downloaded": idx, "total": N, "current_file": "..."}``
        ``{"stage": "done", "downloaded": N, "total": N, "files": {name: bytes}}``
        ``{"stage": "error", "error": "message"}``
    """
    merged_hdrs = {**_REQUEST_HEADERS, **(extra_headers or {})}
    num_files = len(file_list)
    collected: dict[str, bytes] = {}
    conn = aiohttp.TCPConnector(limit=5, limit_per_host=2)

    try:
        async with aiohttp.ClientSession(connector=conn) as sess:
            yield {"stage": "connecting"}
            tmo = aiohttp.ClientTimeout(total=timeout_sec)

            for file_idx, fname in enumerate(file_list):
                target = f"{base_url}{fname}"
                yield {
                    "stage": "downloading",
                    "downloaded": file_idx,
                    "total": num_files,
                    "current_file": fname,
                }
                try:
                    async with sess.get(target, timeout=tmo, headers=merged_hdrs) as resp:
                        resp.raise_for_status()
                        collected[fname] = await resp.read()
                except Exception as exc:
                    log.warning("Failed to fetch %s: %s", fname, exc)

            yield {
                "stage": "done",
                "downloaded": num_files,
                "total": num_files,
                "files": collected,
            }
    except Exception as exc:
        log.error("Batch fetch session error: %s", exc)
        yield {"stage": "error", "error": str(exc)}


# ===================================================================
# Backward-compatible aliases
# ===================================================================
download = fetch_feed
download_with_progress = fetch_with_updates
download_text = fetch_feed_text
download_multifile = fetch_feed_batch
download_multifile_with_progress = fetch_feed_batch_with_updates

# Keep old constant accessible
DEFAULT_HEADERS = _REQUEST_HEADERS
