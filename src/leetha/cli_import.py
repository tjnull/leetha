"""CLI handler for the 'leetha import' command."""
from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from leetha.import_pcap import validate_pcap_file, process_pcap, ImportProgress
from leetha.config import get_config
from leetha.store.database import Database
from leetha.store.store import Store

console = Console()


async def run_import(args) -> None:
    """Import one or more PCAP files through the fingerprinting pipeline."""
    files = [Path(f) for f in args.files]
    max_size = getattr(args, "max_size", 500)

    # Validate all files first
    for f in files:
        err = validate_pcap_file(f, max_size_mb=max_size)
        if err:
            console.print(f"[red]Error:[/red] {err}")
            return

    # Initialize databases (old + new store)
    console.print("[dim]Initializing fingerprint engine...[/dim]")
    config = get_config()
    db_path = Path(config.data_dir) / "leetha.db"
    db = Database(db_path)
    await db.initialize()

    store = Store(db_path)
    await store.initialize()

    # Trigger processor auto-discovery so Pipeline sees all protocols
    import leetha.processors  # noqa: F401

    from leetha.core.pipeline import Pipeline
    pipeline = Pipeline(store=store)

    # Create a packet queue for processing
    packet_queue: asyncio.Queue = asyncio.Queue()

    try:
        for filepath in files:
            console.print(f"\n[bold]Importing:[/bold] {filepath.name}")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total} packets"),
                TimeElapsedColumn(),
                console=console,
            ) as progress_bar:
                task_id = progress_bar.add_task(filepath.name, total=0)

                def on_progress(p: ImportProgress):
                    progress_bar.update(task_id, total=p.total_packets, completed=p.processed)

                result = await process_pcap(
                    filepath,
                    packet_queue,
                    on_progress=on_progress,
                )

            # Drain the queue through the pipeline so every device
            # gets a host record, sighting, and verdict.
            processed = 0
            while not packet_queue.empty():
                pkt = packet_queue.get_nowait()
                try:
                    await pipeline.process(pkt)
                    processed += 1
                except Exception:
                    pass

            # Summary
            table = Table(title=f"Import Complete: {filepath.name}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Packets parsed", str(result.processed))
            table.add_row("Devices processed", str(processed))
            table.add_row("Total packets", str(result.total_packets))
            table.add_row("Parse errors", str(result.errors))
            console.print(table)

        host_count = await store.hosts.count()
        console.print(f"\n[bold]{host_count}[/bold] devices now in inventory")
    finally:
        await store.close()
        await db.close()

    console.print("\n[bold green]All imports complete.[/bold green]")
