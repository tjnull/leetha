"""Sync subsystem — download and update fingerprint databases."""

from __future__ import annotations

from collections.abc import AsyncGenerator


def _format_bytes(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


async def run_sync(list_sources: bool = False, source: str | None = None):
    """CLI entry point for the sync command with progress bars."""
    from leetha.sync.registry import SourceRegistry
    from leetha.config import get_config
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        DownloadColumn, TransferSpeedColumn, TimeRemainingColumn,
        TaskProgressColumn,
    )

    console = Console()
    registry = SourceRegistry()
    config = get_config()

    if list_sources:
        table = Table(
            show_header=True, show_edge=False, pad_edge=True, box=None,
            expand=False, padding=(0, 2),
        )
        table.add_column("Source", style="bold cyan", min_width=20)
        table.add_column("Type", style="dim", width=14)
        table.add_column("Description")
        for src in registry.list_sources():
            table.add_row(src.display_name, src.source_type, src.description)
        console.print()
        console.print("  [bold white]Fingerprint Sources[/bold white]  [dim]── available databases[/dim]")
        console.print()
        console.print(table)
        console.print()
        return

    # Determine which sources to sync
    if source:
        src = registry.get_source(source)
        if not src:
            console.print(f"  [red]✗[/red] Unknown source: [bold]{source}[/bold]")
            return
        source_names = [src.name]
    else:
        source_names = [s.name for s in registry.list_sources()]

    config.cache_dir.mkdir(parents=True, exist_ok=True)

    total_sources = len(source_names)
    succeeded = 0
    failed = 0
    total_entries = 0
    total_bytes = 0

    console.print()
    console.print(
        f"  [bold white]Syncing Fingerprint Databases[/bold white]  "
        f"[dim]── {total_sources} sources[/dim]"
    )
    console.print()

    # Overall progress bar + per-source download bar
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]", justify="left"),
        BarColumn(bar_width=30, style="dim", complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        console=console,
        transient=False,
    ) as progress:
        # Overall task
        overall_task = progress.add_task(
            "Overall", total=total_sources, status=""
        )

        for idx, src_name in enumerate(source_names):
            # Per-source task
            src_task = progress.add_task(
                f"  {registry.get_source(src_name).display_name}",
                total=None,
                status="connecting...",
            )

            source_ok = False
            source_entries = 0
            source_bytes = 0

            async for event in sync_source_with_progress(src_name):
                etype = event["event"]

                if etype == "downloading":
                    dl = event.get("downloaded", 0)
                    dl_total = event.get("total")
                    unit = event.get("unit", "bytes")

                    if unit == "files":
                        progress.update(
                            src_task,
                            total=dl_total,
                            completed=dl,
                            status=f"{dl}/{dl_total} files",
                        )
                    elif dl_total:
                        progress.update(
                            src_task,
                            total=dl_total,
                            completed=dl,
                            status=_format_bytes(dl),
                        )
                    else:
                        progress.update(
                            src_task,
                            total=None,
                            completed=dl,
                            status=_format_bytes(dl),
                        )

                elif etype == "parsing":
                    progress.update(src_task, status="parsing...")

                elif etype == "complete":
                    source_entries = event.get("entries", 0)
                    source_bytes = event.get("size", 0)
                    progress.update(
                        src_task,
                        total=1,
                        completed=1,
                        status=f"[green]✓ {source_entries:,} entries[/green]",
                    )
                    source_ok = True

                elif etype == "error":
                    progress.update(
                        src_task,
                        total=1,
                        completed=1,
                        status=f"[red]✗ {event.get('error', 'failed')}[/red]",
                    )

            if source_ok:
                succeeded += 1
                total_entries += source_entries
                total_bytes += source_bytes
            else:
                failed += 1

            progress.update(overall_task, completed=idx + 1)

    # Summary
    console.print()
    if failed == 0:
        console.print(
            f"  [green]✓[/green] [bold]{succeeded}/{total_sources}[/bold] sources synced  "
            f"[dim]│[/dim]  [bold]{total_entries:,}[/bold] entries  "
            f"[dim]│[/dim]  {_format_bytes(total_bytes)}"
        )
    else:
        console.print(
            f"  [yellow]![/yellow] [bold]{succeeded}[/bold] synced, "
            f"[red]{failed}[/red] failed  "
            f"[dim]│[/dim]  [bold]{total_entries:,}[/bold] entries  "
            f"[dim]│[/dim]  {_format_bytes(total_bytes)}"
        )
    console.print()


PARSER_MAP = {
    "ieee_oui": "parse_oui_csv",
    "p0f": "parse_p0f",
    "huginn_devices": "parse_huginn_devices",
    "huginn_combinations": "parse_huginn_combinations",
    "huginn_dhcp": "parse_huginn_dhcp",
    "huginn_dhcp_vendor": "parse_huginn_dhcp_vendor",
    "huginn_dhcpv6": "parse_huginn_dhcpv6",
    "huginn_dhcpv6_enterprise": "parse_huginn_dhcpv6_enterprise",
    "huginn_mac_vendors": "parse_huginn_mac_vendors",
    "iana_enterprise": "parse_iana_enterprise",
    "ja3_fingerprints": "parse_ja3_database",
    "ja4_fingerprints": "parse_ja4_database",
    "satori_dhcp": "parse_satori",
    "satori_useragent": "parse_satori",
    "satori_tcp": "parse_satori",
    "satori_smb": "parse_satori",
    "satori_ssh": "parse_satori",
    "satori_web": "parse_satori",
    "satori_sip": "parse_satori",
    "satori_ntp": "parse_satori",
}

CACHE_NAMES = {
    "ja3_fingerprints": "ja3",
    "ja4_fingerprints": "ja4",
}

# File lists for git_multifile sources.
# Upstream Huginn-Muninn reorganized its JSON exports into numbered
# ``_partNN`` shards; keep these manifests in sync with the repo tree.
MULTIFILE_MANIFESTS: dict[str, list[str]] = {
    # MAC_Vendors: 34 sequential parts plus one trailing p35_c1 shard.
    "huginn_mac_vendors": (
        [f"mac_vendor_part{n:02d}.json" for n in range(1, 35)]
        + ["mac_vendor_p35_c1.json"]
    ),
    # DHCP_Signatures: dhcp_signature.json was split into 2 fingerprint parts.
    "huginn_dhcp": [
        "dhcp_fingerprint_part01.json",
        "dhcp_fingerprint_part02.json",
    ],
    # DHCP_Vendors: dhcp_vendor.json was split into 2 parts.
    "huginn_dhcp_vendor": [
        "dhcp_vendor_part01.json",
        "dhcp_vendor_part02.json",
    ],
}


async def sync_source_with_progress(source_name: str) -> AsyncGenerator[dict, None]:
    """Sync a single source, yielding progress events."""
    from leetha.sync.registry import SourceRegistry
    from leetha.sync.downloader import download_with_progress, download_multifile_with_progress
    from leetha.sync import parsers
    from leetha.config import get_config
    import json

    registry = SourceRegistry()
    config = get_config()
    config.cache_dir.mkdir(parents=True, exist_ok=True)

    src = registry.get_source(source_name)
    if not src:
        yield {"event": "error", "source": source_name, "error": f"Unknown source: {source_name}"}
        return

    yield {
        "event": "start",
        "source": src.name,
        "display_name": src.display_name,
        "url": src.url,
        "source_type": src.source_type,
        "description": src.description,
    }

    parser_fn_name = PARSER_MAP.get(src.name)
    if not parser_fn_name:
        yield {"event": "error", "source": src.name, "error": f"No parser for {src.name}"}
        return

    # Multifile sources (e.g. huginn_mac_vendors with 31 JSON files)
    if src.source_type == "git_multifile":
        filenames = MULTIFILE_MANIFESTS.get(src.name, [])
        if not filenames:
            yield {"event": "error", "source": src.name, "error": f"No file manifest for {src.name}"}
            return

        file_data: dict[str, bytes] = {}
        async for progress in download_multifile_with_progress(src.url, filenames):
            if progress["stage"] == "connecting":
                yield {"event": "downloading", "source": src.name, "downloaded": 0, "total": len(filenames)}
            elif progress["stage"] == "downloading":
                yield {
                    "event": "downloading",
                    "source": src.name,
                    "downloaded": progress["downloaded"],
                    "total": progress["total"],
                    "unit": "files",
                    "current_file": progress.get("current_file"),
                }
            elif progress["stage"] == "done":
                file_data = progress["files"]
            elif progress["stage"] == "error":
                yield {"event": "error", "source": src.name, "error": progress["error"]}
                return

        if not file_data:
            yield {"event": "error", "source": src.name, "error": "Multifile download returned no data"}
            return

        yield {"event": "parsing", "source": src.name}

        try:
            parser_fn = getattr(parsers, parser_fn_name)
            merged: dict = {}
            total_bytes = 0
            for fname, raw in file_data.items():
                total_bytes += len(raw)
                chunk_content = raw.decode("utf-8", errors="ignore")
                chunk_data = parser_fn(chunk_content)
                if isinstance(chunk_data, dict):
                    merged.update(chunk_data)

            cache_name = CACHE_NAMES.get(src.name, src.name)
            cache_file = config.cache_dir / f"{cache_name}.json"
            with open(cache_file, "w") as f:
                json.dump({"source": src.name, "entries": merged}, f)

            yield {
                "event": "complete",
                "source": src.name,
                "entries": len(merged),
                "size": total_bytes,
            }
        except Exception as e:
            yield {"event": "error", "source": src.name, "error": str(e)}
        return

    # Single-file sources — stream large downloads to a temp file to
    # avoid holding hundreds of MB as bytes + decoded string in memory.
    import tempfile as _tf

    tmp_file = _tf.SpooledTemporaryFile(max_size=4 * 1024 * 1024, mode="w+b")
    download_size = 0
    async for progress in download_with_progress(src.url, dest_file=tmp_file):
        if progress["stage"] == "connecting":
            yield {"event": "downloading", "source": src.name, "downloaded": 0, "total": None}
        elif progress["stage"] == "downloading":
            yield {
                "event": "downloading",
                "source": src.name,
                "downloaded": progress["downloaded"],
                "total": progress.get("total"),
            }
        elif progress["stage"] == "done":
            download_size = progress["downloaded"]
        elif progress["stage"] == "error":
            tmp_file.close()
            yield {"event": "error", "source": src.name, "error": progress["error"]}
            return

    if download_size == 0:
        tmp_file.close()
        yield {"event": "error", "source": src.name, "error": "Download returned no data"}
        return

    tmp_file.seek(0)
    content = tmp_file.read().decode("utf-8", errors="ignore")
    tmp_file.close()

    # Parse
    yield {"event": "parsing", "source": src.name}

    try:
        parser_fn = getattr(parsers, parser_fn_name)
        data = parser_fn(content)

        cache_name = CACHE_NAMES.get(src.name, src.name)
        cache_file = config.cache_dir / f"{cache_name}.json"
        with open(cache_file, "w") as f:
            json.dump({"source": src.name, "entries": data}, f)

        count = len(data) if isinstance(data, (dict, list)) else 0
        yield {
            "event": "complete",
            "source": src.name,
            "entries": count,
            "size": download_size,
        }
    except Exception as e:
        yield {"event": "error", "source": src.name, "error": str(e)}


async def sync_all_with_progress() -> AsyncGenerator[dict, None]:
    """Sync all sources, yielding progress events."""
    from leetha.sync.registry import SourceRegistry
    registry = SourceRegistry()
    sources = registry.list_sources()

    yield {"event": "sync_start", "total_sources": len(sources)}

    succeeded = 0
    failed = 0

    for idx, src in enumerate(sources):
        yield {"event": "source_index", "index": idx, "total_sources": len(sources)}
        async for event in sync_source_with_progress(src.name):
            yield event
            if event["event"] == "complete":
                succeeded += 1
            elif event["event"] == "error":
                failed += 1

    yield {
        "event": "sync_complete",
        "total_sources": len(sources),
        "succeeded": succeeded,
        "failed": failed,
    }
