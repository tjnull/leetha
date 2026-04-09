"""Interactive async REPL console for LEETHA passive network fingerprinting.

Provides a command-driven interface for managing fingerprint databases,
running live capture sessions, viewing discovered devices and alerts,
and launching the web dashboard.
"""

from __future__ import annotations

import asyncio
import json
import os
try:
    import readline  # noqa: F401  — input() history/editing on Unix
except ImportError:
    try:
        import pyreadline3  # noqa: F401  — Windows alternative
    except ImportError:
        pass  # No line editing — input() still works, just no history
import shlex
import signal
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from leetha.app import LeethaApp
from leetha.capture.interfaces import (
    InterfaceConfig, DetectedInterface,
    detect_interfaces, get_routes, enrich_interfaces, sort_interfaces,
)
from leetha.config import get_config
from leetha.store.database import Database
from leetha.store.store import Store
from leetha.sync import CACHE_NAMES
from leetha.sync.registry import SourceRegistry
from leetha.ui.live import run_live
from leetha.ui.web.app import run_web_async

DEVICE_TYPE_DISPLAY: dict[str, str] = {
    "router": "Router", "switch": "Switch", "firewall": "Firewall",
    "access_point": "AP", "ap": "AP", "wap": "AP", "gateway": "Gateway",
    "bridge": "Bridge", "mesh_router": "Mesh Router", "workstation": "PC",
    "laptop": "Laptop", "server": "Server", "desktop": "Desktop",
    "computer": "Computer", "pc": "PC", "thin_client": "Thin Client",
    "mobile": "Mobile", "phone": "Phone", "smartphone": "Phone",
    "tablet": "Tablet", "smart_tv": "Smart TV", "tv": "TV",
    "smart_speaker": "Speaker", "smart_display": "Display",
    "game_console": "Console", "media_player": "Media",
    "media_server": "Media Srv", "streaming": "Streaming",
    "streaming_device": "Streaming", "set_top_box": "STB", "iot": "IoT",
    "camera": "Camera", "ip_camera": "IP Camera", "sensor": "Sensor",
    "thermostat": "Thermostat", "doorbell": "Doorbell",
    "smart_plug": "Smart Plug", "smart_lighting": "Lighting",
    "smart_lock": "Lock", "home_hub": "Home Hub", "nas": "NAS",
    "san": "SAN", "printer": "Printer", "scanner": "Scanner",
    "multifunction": "MFP", "voip_phone": "VoIP", "plc": "PLC",
    "hmi": "HMI", "hypervisor": "Hypervisor", "virtual_machine": "VM",
    "esxi": "ESXi", "vcenter": "vCenter", "proxmox": "Proxmox",
    "hyper_v": "Hyper-V", "kvm_host": "KVM Host",
    "virtual_router": "vRouter", "xen": "Xen", "container": "Container",
    "container_host": "Docker Host", "docker_host": "Docker Host",
    "kubernetes_node": "K8s Node", "kubernetes_master": "K8s Master",
    "container_registry": "Registry", "openshift": "OpenShift",
    "load_balancer": "Load Bal.", "sdwan": "SD-WAN", "embedded": "Embedded",
    "wearable": "Wearable", "automotive": "Vehicle",
    "microcontroller": "MCU", "Unknown": "Unknown",
}


def _display_type(raw_type: str | None) -> str:
    """Convert internal device_type to clean display name."""
    if not raw_type:
        return "—"
    if " " in raw_type or raw_type[0].isupper():
        return raw_type
    return DEVICE_TYPE_DISPLAY.get(raw_type, raw_type.replace("_", " ").title())


# Command registry: (name, aliases, usage, description)

_COMMANDS: list[tuple[str, list[str], str, str]] = [
    ("help",      ["h", "?"],         "help",                              "Show this help message"),
    ("list",      ["ls"],             "list interfaces",                   "List detected network interfaces"),
    ("use",       [],                 "use interface 1 3 | use interface eth0", "Select capture interfaces by # or name"),
    ("sync",      ["s"],              "sync [--source NAME] [--list]",     "Download/update fingerprint databases"),
    ("sources",   ["src"],            "sources",                           "Show available sources with sync status"),
    ("devices",   ["d", "dev"],       "devices [--all]",                   "List discovered devices"),
    ("alerts",    ["a"],              "alerts",                            "List active alerts"),
    ("status",    ["st"],             "status",                            "Show system status"),
    ("start",     ["capture"],        "start | start web | start cli",     "Start capture, web dashboard, or live stream"),
    ("stop",      [],                 "stop",                              "Stop packet capture"),
    ("probe",     [],                 "probe <status|enable|disable|run|list>", "Manage active probing"),
    ("clear",     ["cls"],            "clear",                             "Clear the terminal"),
    ("exit",      ["quit", "q"],      "exit",                              "Exit LEETHA (or Ctrl+C)"),
    # Hidden aliases for backward compatibility
    ("interface", ["iface", "if"],    "",                                  ""),
    ("live",      ["l"],              "",                                  ""),
    ("web",       ["w"],              "",                                  ""),
]

# Build alias -> canonical name lookup
_ALIAS_MAP: dict[str, str] = {}
for _name, _aliases, _, _ in _COMMANDS:
    _ALIAS_MAP[_name] = _name
    for _a in _aliases:
        _ALIAS_MAP[_a] = _name

# Per-command sub-completions: command -> list of (token, description)
_COMMAND_SUBS: dict[str, list[tuple[str, str]]] = {
    "list": [("interfaces", "Show detected network interfaces")],
    "use": [("interface", "Select capture interfaces by # or name")],
    "start": [
        ("web", "Launch web dashboard"),
        ("cli", "Launch live packet stream"),
    ],
    "interface": [
        ("list", "Show detected interfaces"),
        ("clear", "Deselect all interfaces"),
    ],
    "sync": [
        ("--source", "Sync a specific source"),
        ("--list", "List available sources"),
    ],
    "live": [
        ("--decode", "Show decoded packet fields"),
        ("--filter", "BPF filter expression"),
        ("--rate", "Max packets per second"),
    ],
    "web": [
        ("--port", "HTTP port (default 8080)"),
        ("--host", "Bind address (default 0.0.0.0)"),
    ],
    "devices": [("--all", "Show all MAC rows instead of identities")],
    "probe": [
        ("status", "Show interface probe modes"),
        ("enable", "Enable probing on interface (OPSEC warning)"),
        ("disable", "Disable probing on interface"),
        ("run", "Run probe(s) on interface"),
        ("list", "List available probe types"),
    ],
}

# Flat token lists for matching
_COMMAND_FLAGS: dict[str, list[str]] = {
    cmd: [token for token, _ in subs] for cmd, subs in _COMMAND_SUBS.items()
}

# Description lookup for display hook: command -> {token: description}
_SUB_DESCRIPTIONS: dict[str, dict[str, str]] = {
    cmd: {token: desc for token, desc in subs} for cmd, subs in _COMMAND_SUBS.items()
}

# Visible commands with descriptions for display hook
_CMD_DESCRIPTIONS: dict[str, str] = {}
for _name, _aliases_list, _usage, _desc in _COMMANDS:
    if _desc:  # skip hidden commands
        _CMD_DESCRIPTIONS[_name] = _desc
        for _a in _aliases_list:
            _CMD_DESCRIPTIONS[_a] = f"(alias for {_name})"


class LeethaCompleter:
    """readline tab-completer for the leetha console with descriptive display."""

    def __init__(self) -> None:
        self._matches: list[str] = []
        self._line: str = ""
        self._current_cmd: str = ""  # track context for display hook
        # All completable first-words: canonical names + aliases
        self._commands = sorted(_ALIAS_MAP.keys())

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            self._build_matches(text)
        if state < len(self._matches):
            match = self._matches[state]
            # Append trailing space so cursor advances past completed word
            return match + " " if not match.endswith(" ") else match
        return None

    def _build_matches(self, text: str) -> None:
        # Use _line override (for tests) or readline buffer
        if self._line:
            line = self._line
        else:
            try:
                line = readline.get_line_buffer()
            except AttributeError:
                line = text

        parts = line.lstrip().split()
        # Completing first word (command name)
        if len(parts) <= 1 and not line.endswith(" "):
            self._current_cmd = ""
            # Only show visible commands (skip hidden aliases) for first-word completion
            visible_cmds = set()
            for _name, _aliases, _usage, _desc in _COMMANDS:
                if _desc:  # skip hidden commands
                    visible_cmds.add(_name)
                    for a in _aliases:
                        visible_cmds.add(a)
            self._matches = sorted(c for c in visible_cmds if c.startswith(text))
        else:
            # Completing sub-arguments for a known command
            cmd = _ALIAS_MAP.get(parts[0].lower(), "")
            self._current_cmd = cmd
            flags = _COMMAND_FLAGS.get(cmd, [])
            self._matches = [f for f in flags if f.startswith(text)]

    def display_hook(self, substitution: str, matches: list[str], longest_match_length: int) -> None:
        """Custom readline display hook showing descriptions alongside completions."""
        # Determine which description set to use
        if self._current_cmd:
            desc_map = _SUB_DESCRIPTIONS.get(self._current_cmd, {})
        else:
            desc_map = _CMD_DESCRIPTIONS

        # Print matches with descriptions
        import sys
        sys.stdout.write("\n")
        for match in sorted(matches):
            clean = match.rstrip()  # strip trailing space added by complete()
            desc = desc_map.get(clean, "")
            if desc:
                sys.stdout.write(f"  \033[1;36m{clean:<20}\033[0m \033[2m{desc}\033[0m\n")
            else:
                sys.stdout.write(f"  \033[1;36m{clean}\033[0m\n")
        sys.stdout.flush()
        readline.redisplay()


class LeethaConsole:
    """Interactive async REPL for LEETHA."""

    def __init__(self, interfaces: list | None = None, initial_command: str | None = None) -> None:
        self.interfaces = interfaces
        self.initial_command = initial_command
        self.console = Console(emoji=False)
        self.config = get_config()
        self.app: LeethaApp | None = None
        self.db: Database | None = None
        self._store: Store | None = None
        self._running = True
        self._completer = LeethaCompleter()

    def _build_prompt(self) -> str:
        """Build the REPL prompt, showing capture status when active."""
        if self.app is not None and self.interfaces:
            iface_names = ",".join(i.name for i in self.interfaces)
            return f"leetha [capture: {iface_names}]> "
        return "leetha> "

    @property
    def _active_store(self) -> Store | None:
        """Get the active Store -- from app if running, otherwise standalone."""
        if self.app and hasattr(self.app, 'store') and self.app.store:
            return self.app.store
        return self._store

    # Main loop

    async def run(self) -> None:
        """Run the REPL until the user exits."""
        # Skip banner when re-launched with sudo (interfaces pre-selected)
        if not self.interfaces:
            self._print_banner()
            # Offer to sync sources if none (or few) are cached
            await self._maybe_prompt_sync()

        # Initialize database
        self.db = Database(self.config.db_path)
        await self.db.initialize()

        # Initialize standalone Store for console queries
        self._store = Store(self.config.db_path)
        await self._store.initialize()

        loop = asyncio.get_event_loop()

        # Ctrl+C raises KeyboardInterrupt; the REPL loop or sub-mode
        # handler decides what to do with it.
        def _sigint_handler(sig, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, _sigint_handler)

        # Set up tab completion
        old_completer = readline.get_completer()
        old_delims = readline.get_completer_delims()
        readline.set_completer(self._completer.complete)
        readline.set_completion_display_matches_hook(self._completer.display_hook)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t\n")
        # Suppress default filename fallback
        if hasattr(readline, "set_auto_history"):
            readline.set_auto_history(True)

        # Auto-start capture if interfaces were provided via CLI (-i flag).
        # This happens after sudo re-exec: the user already selected an
        # interface, got prompted for password, and now we have privileges.
        if self.interfaces and self.app is None:
            self.app = LeethaApp(interfaces=self.interfaces)
            await self.app.start()
            if self.app.capture_engine._workers:
                names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
                self._success(f"Capture started on {names}")
                self.console.print()
                self.console.print("  [bold white]What's next?[/bold white]")
                self.console.print()
                for cmd, desc in [
                    ("start web",  "Open the browser-based dashboard"),
                    ("start cli", "Stream packets with fingerprint reasoning"),
                    ("devices",   "View discovered devices"),
                    ("alerts",    "View active security alerts"),
                ]:
                    self.console.print(f"    [bold cyan]{cmd:<12s}[/bold cyan] [dim]{desc}[/dim]")
                self.console.print()

        # Auto-execute initial command (from startup wizard)
        if self.initial_command:
            cmd = self.initial_command
            self.initial_command = None
            await self._dispatch(cmd)

        try:
            while self._running:
                try:
                    line = await loop.run_in_executor(
                        None, lambda: input(self._build_prompt())
                    )
                except (EOFError, KeyboardInterrupt):
                    break

                stripped = line.strip()
                if not stripped:
                    continue

                await self._dispatch(stripped)
        finally:
            # Restore default SIGINT so lingering executor threads
            # don't raise KeyboardInterrupt during shutdown.
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            readline.set_completer(old_completer)
            readline.set_completer_delims(old_delims)
            readline.set_completion_display_matches_hook(None)
            self.console.print("\n  [dim]Goodbye.[/dim]\n")
            if self.app is not None:
                await self.app.stop()
                self.app = None
            if self.db is not None:
                await self.db.close()
            if self._store is not None:
                await self._store.close()
                self._store = None

    # Dispatch

    async def _dispatch(self, line: str) -> None:
        """Parse *line* and dispatch to the appropriate ``_cmd_*`` handler."""
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self.console.print(f"[red]Parse error: {exc}[/red]")
            return

        if not parts:
            return

        raw_cmd = parts[0].lower()
        args = parts[1:]

        # Resolve aliases
        canonical = _ALIAS_MAP.get(raw_cmd)
        if canonical is None:
            # Fuzzy match: suggest closest command
            from difflib import get_close_matches
            candidates = list(_ALIAS_MAP.keys())
            matches = get_close_matches(raw_cmd, candidates, n=1, cutoff=0.6)
            if matches:
                self._error(f"Unknown command: [bold]{raw_cmd}[/bold]")
                self._hint(f"Did you mean [bold cyan]{matches[0]}[/bold cyan]?")
            else:
                self._error(f"Unknown command: [bold]{raw_cmd}[/bold]")
                self._hint("Type [bold cyan]help[/bold cyan] for available commands")
            return

        handler = getattr(self, f"_cmd_{canonical}", None)
        if handler is None:
            return

        try:
            await handler(args)
        except KeyboardInterrupt:
            # Ctrl+C during a command → exit the whole app
            self._running = False
        except Exception as exc:
            self._error(str(exc))

    # Banner

    _LOGO = r"""
[bold blue]  ██╗     ███████╗███████╗████████╗██╗  ██╗ █████╗[/bold blue]
[bold blue]  ██║     ██╔════╝██╔════╝╚══██╔══╝██║  ██║██╔══██╗[/bold blue]
[bold cyan]  ██║     █████╗  █████╗     ██║   ███████║███████║[/bold cyan]
[bold cyan]  ██║     ██╔══╝  ██╔══╝     ██║   ██╔══██║██╔══██║[/bold cyan]
[dim cyan]  ███████╗███████╗███████╗   ██║   ██║  ██║██║  ██║[/dim cyan]
[dim cyan]  ╚══════╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝[/dim cyan]
"""

    # Interface type icons for the startup display
    _IFACE_ICONS: dict[str, str] = {
        "ethernet": "󰈀",
        "wireless": "󰖩",
        "tunnel":   "󰕥",
        "bridge":   "󰌘",
        "loopback": "󰑐",
        "virtual":  "󰌘",
    }

    def _print_banner(self) -> None:
        """Display the welcome banner with ASCII logo, status, and interfaces."""
        self.console.print(self._LOGO)
        self.console.print(
            "  [dim]Passive Network Fingerprinting[/dim]        "
            "[dim]Type[/dim] [bold cyan]help[/bold cyan] [dim]for commands,[/dim] "
            "[bold]Ctrl+C[/bold] [dim]to exit[/dim]"
        )

        # Status bar
        synced = self._count_synced_sources()
        total = len(SourceRegistry().list_sources())
        db_tag = "[green]ready[/green]" if self.config.db_path.is_file() else "[yellow]new[/yellow]"
        src_color = "green" if synced == total else "yellow"

        self.console.print()
        self.console.print(
            f"  [dim]Sources:[/dim] [{src_color}]{synced}/{total}[/{src_color}]  "
            f"[dim]│[/dim]  [dim]DB:[/dim] {db_tag}  "
            f"[dim]│[/dim]  [dim]Path:[/dim] [dim white]{self.config.db_path}[/dim white]"
        )

        # Auto-detect and display interfaces (skip full table if already selected)
        self.console.print()
        if self.interfaces:
            # Compact display when interfaces are pre-selected (e.g., after sudo re-exec)
            iface_names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
            self.console.print(f"  [dim]Interface:[/dim] {iface_names}")
            return

        detected = self._detect_interfaces()
        selected_names: set[str] = set()

        if detected:
            table = Table(
                show_header=True,
                show_edge=False,
                pad_edge=True,
                box=None,
                expand=False,
                padding=(0, 2),
            )
            table.add_column("#", style="bold dim", width=4, justify="right")
            table.add_column("Interface", style="bold cyan", width=14)
            table.add_column("State", width=8)
            table.add_column("Type", style="dim", width=12)
            table.add_column("MAC", style="dim", no_wrap=True, width=20)
            table.add_column("Address", style="white", min_width=16)
            table.add_column("", width=3, justify="center")

            for idx, iface in enumerate(detected, 1):
                ipv4s = [b.address for b in iface.bindings if b.family == "ipv4"]
                addr = ", ".join(ipv4s) if ipv4s else "[dim]\u2014[/dim]"
                mac = iface.mac or "[dim]\u2014[/dim]"
                icon = self._IFACE_ICONS.get(iface.type, "")

                if iface.state == "up":
                    state = "[green]\u25cf up[/green]"
                else:
                    state = "[dim red]\u25cb down[/dim red]"

                selected = "[bold green]\u2713[/bold green]" if iface.name in selected_names else ""
                type_label = f"{icon} {iface.type}" if icon else iface.type

                table.add_row(str(idx), iface.name, state, type_label, mac, addr, selected)

            self.console.print(
                "  [bold white]Interfaces[/bold white]  [dim]── detected on this system[/dim]"
            )
            self.console.print(table)
        else:
            self.console.print("  [red]No network interfaces detected.[/red]")

        # Quick-start hint
        self.console.print()
        if self.interfaces:
            iface_names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
            if self.app is not None:
                self.console.print(
                    f"  [green]\u25b6[/green] Capturing on {iface_names}"
                )
            else:
                self.console.print(
                    f"  [yellow]\u25a0[/yellow] Selected: {iface_names}  "
                    "[dim]─[/dim]  [bold]start[/bold] [dim]to begin capture[/dim]"
                )
        else:
            self.console.print(
                "  [dim]Select one or more interfaces by number or name to start passive capture.[/dim]\n"
                "  [dim]Single:[/dim]   [bold cyan]use interface eth0[/bold cyan]          "
                "[dim]Multi:[/dim]  [bold cyan]use interface eth0 wlan0[/bold cyan]"
            )
        self.console.print()

    # Helpers

    def _count_synced_sources(self) -> int:
        """Count how many source cache files exist on disk."""
        registry = SourceRegistry()
        count = 0
        for src in registry.list_sources():
            cache_name = CACHE_NAMES.get(src.name, src.name)
            if (self.config.cache_dir / f"{cache_name}.json").is_file():
                count += 1
        return count

    async def _maybe_prompt_sync(self) -> None:
        """Prompt user to sync fingerprint sources if few or none are cached."""
        synced = self._count_synced_sources()
        total = len(SourceRegistry().list_sources())
        if synced >= total:
            return  # All sources present

        if synced == 0:
            msg = "  [yellow]No fingerprint sources are cached.[/yellow]"
        else:
            msg = f"  [yellow]Only {synced}/{total} fingerprint sources are cached.[/yellow]"

        self.console.print(msg)
        self.console.print(
            "  [dim]Syncing sources improves device identification accuracy.[/dim]"
        )
        self.console.print()

        try:
            answer = input("  Sync sources now? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            self.console.print()
            return

        if answer in ("", "y", "yes"):
            from leetha.sync import run_sync
            await run_sync()
            self.console.print()
        else:
            self.console.print(
                "  [dim]Skipped — run[/dim] [bold cyan]sync[/bold cyan] "
                "[dim]any time to download sources.[/dim]"
            )
            self.console.print()

    # Commands

    # ── Section header helper ──────────────────────────────────────

    def _section(self, title: str, subtitle: str = "") -> None:
        """Print a styled section header."""
        sub = f"  [dim]── {subtitle}[/dim]" if subtitle else ""
        self.console.print(f"\n  [bold white]{title}[/bold white]{sub}\n")

    def _success(self, msg: str) -> None:
        self.console.print(f"  [green]✓[/green] {msg}")

    def _warn(self, msg: str) -> None:
        self.console.print(f"  [yellow]![/yellow] {msg}")

    def _error(self, msg: str) -> None:
        self.console.print(f"  [red]✗[/red] {msg}")

    def _info(self, msg: str) -> None:
        self.console.print(f"  [blue]›[/blue] {msg}")

    def _hint(self, msg: str) -> None:
        self.console.print(f"  [dim]{msg}[/dim]")

    # ── Help ─────────────────────────────────────────────────────

    # Group commands by category for the help display
    _HELP_CATEGORIES: list[tuple[str, list[str]]] = [
        ("Capture",    ["list", "use", "start", "stop"]),
        ("Data",       ["sync", "sources", "devices", "alerts"]),
        ("Probing",    ["probe"]),
        ("System",     ["status", "clear", "help", "exit"]),
    ]

    async def _cmd_help(self, args: list[str]) -> None:
        # Build lookup from command name -> (aliases, usage, description)
        cmd_info: dict[str, tuple[str, str, str]] = {}
        for name, aliases, usage, desc in _COMMANDS:
            if desc:
                cmd_info[name] = (", ".join(aliases) if aliases else "", usage, desc)

        self._section("Commands", "grouped by category")

        for category, cmd_names in self._HELP_CATEGORIES:
            self.console.print(f"  [bold blue]{category}[/bold blue]")
            for name in cmd_names:
                info = cmd_info.get(name)
                if not info:
                    continue
                alias_str, usage, desc = info
                alias_part = f" [dim]({alias_str})[/dim]" if alias_str else ""
                self.console.print(
                    f"    [bold cyan]{name:<12s}[/bold cyan]{alias_part}"
                )
                self.console.print(f"    [dim]  {desc}[/dim]")
                if usage:
                    self.console.print(f"    [dim]  Usage: {usage}[/dim]")
            self.console.print()

        self.console.print("  [bold white]Quick Start[/bold white]")
        self.console.print()
        quick = [
            ("use interface eth0 wlan0", "Select interfaces and auto-start capture"),
            ("start web", "Launch the web dashboard"),
            ("start cli", "Stream live packets with fingerprint reasoning"),
            ("devices", "View all discovered devices on the network"),
        ]
        for cmd, desc in quick:
            self.console.print(f"    [bold cyan]{cmd:<30s}[/bold cyan] [dim]{desc}[/dim]")
        self.console.print()

    async def _cmd_list(self, args: list[str]) -> None:
        """Handle 'list interfaces'."""
        if not args or args[0] == "interfaces":
            await self._cmd_interface(["list"])
        else:
            self._error(f"Unknown list target: [bold]{args[0]}[/bold]")
            self._hint("Available: [bold cyan]list interfaces[/bold cyan]")

    async def _cmd_use(self, args: list[str]) -> None:
        """Handle 'use interface eth0 wlan0'."""
        if not args:
            self._hint("Usage: [bold cyan]use interface <name|#> ...[/bold cyan]")
            return
        if args[0] in ("interface", "iface", "if"):
            await self._cmd_interface(args[1:] if len(args) > 1 else [])
        else:
            self._error(f"Unknown target: [bold]{args[0]}[/bold]")
            self._hint("Usage: [bold cyan]use interface <name|#> ...[/bold cyan]")



    async def _cmd_sync(self, args: list[str]) -> None:
        from leetha.sync import run_sync

        source = None
        list_sources = False

        if "--list" in args:
            list_sources = True
        elif "--source" in args:
            idx = args.index("--source")
            if idx + 1 < len(args):
                source = args[idx + 1]
            else:
                self._error("[bold]--source[/bold] requires a name")
                return

        await run_sync(list_sources=list_sources, source=source)

    async def _cmd_sources(self, args: list[str]) -> None:
        registry = SourceRegistry()

        self._section("Fingerprint Sources", "databases used for device identification")

        table = Table(
            show_header=True, show_edge=False, pad_edge=True, box=None,
            expand=False, padding=(0, 2),
        )
        table.add_column("Source", style="bold cyan", min_width=20)
        table.add_column("Status", width=10, justify="center")
        table.add_column("Entries", justify="right", width=10)
        table.add_column("Last Synced", width=22, style="dim")

        synced_count = 0
        total_entries = 0

        for src in registry.list_sources():
            cache_name = CACHE_NAMES.get(src.name, src.name)
            cache_file = self.config.cache_dir / f"{cache_name}.json"

            if cache_file.is_file():
                status = "[green]● synced[/green]"
                synced_count += 1
                mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
                last_synced = mtime.strftime("%Y-%m-%d %H:%M")
                try:
                    with open(cache_file) as f:
                        data = json.load(f)
                    entries_data = data.get("entries", data)
                    count = (
                        len(entries_data)
                        if isinstance(entries_data, (dict, list))
                        else 0
                    )
                    entries = f"{count:,}" if isinstance(count, int) else "?"
                    if isinstance(count, int):
                        total_entries += count
                except Exception:
                    entries = "?"
            else:
                status = "[red]○ missing[/red]"
                entries = "[dim]—[/dim]"
                last_synced = "[dim]never[/dim]"

            table.add_row(src.display_name, status, entries, last_synced)

        self.console.print(table)

        total = len(registry.list_sources())
        color = "green" if synced_count == total else "yellow"
        self.console.print(
            f"\n  [{color}]{synced_count}/{total}[/{color}] sources synced  "
            f"[dim]│[/dim]  [bold]{total_entries:,}[/bold] [dim]total entries[/dim]"
        )
        if synced_count < total:
            self._hint("Run [bold cyan]sync[/bold cyan] to download missing databases")
        self.console.print()

    def _detect_interfaces(self) -> list[DetectedInterface]:
        """Detect all system interfaces, sorted: real first, virtual last."""
        return sort_interfaces(detect_interfaces(include_down=True))

    async def _cmd_interface(self, args: list[str]) -> None:
        # "interface clear" — deselect all
        if args and args[0] == "clear":
            if self.app is not None:
                self._warn("Stopping capture first")
                await self.app.stop()
                self.app = None
            self.interfaces = None
            self._success("All interfaces deselected")
            return

        detected = self._detect_interfaces()
        if not detected:
            self._error("No network interfaces detected")
            return

        # "interface list" or bare "interface" — show numbered list
        if not args or (len(args) == 1 and args[0] == "list"):
            selected_names = {i.name for i in self.interfaces} if self.interfaces else set()

            self._section("Network Interfaces", "refresh with [bold cyan]list interfaces[/bold cyan]")

            table = Table(
                show_header=True, show_edge=False, pad_edge=True, box=None,
                expand=False, padding=(0, 2),
            )
            table.add_column("#", style="bold dim", width=4, justify="right")
            table.add_column("Interface", style="bold cyan", width=14)
            table.add_column("State", width=8)
            table.add_column("Type", style="dim", width=12)
            table.add_column("MAC", style="dim", no_wrap=True, width=20)
            table.add_column("Address", style="white", min_width=16)
            table.add_column("", width=3, justify="center")

            for idx, iface in enumerate(detected, 1):
                ipv4s = [b.address for b in iface.bindings if b.family == "ipv4"]
                addr = ", ".join(ipv4s) if ipv4s else "[dim]—[/dim]"
                mac = iface.mac or "[dim]—[/dim]"
                icon = self._IFACE_ICONS.get(iface.type, "")

                if iface.state == "up":
                    state = "[green]● up[/green]"
                else:
                    state = "[dim red]○ down[/dim red]"

                selected = "[bold green]✓[/bold green]" if iface.name in selected_names else ""
                type_label = f"{icon} {iface.type}" if icon else iface.type

                table.add_row(str(idx), iface.name, state, type_label, mac, addr, selected)

            self.console.print(table)
            self.console.print()
            self.console.print(
                "  [dim]Select:[/dim]  [bold cyan]use interface eth0 wlan0[/bold cyan]    "
                "[dim]Clear:[/dim]  [bold cyan]use interface clear[/bold cyan]"
            )
            self.console.print()
            return

        # "interface 1 3" or "interface eth0 wlan0" — select by number or name
        name_map = {iface.name: iface for iface in detected}
        idx_map = {str(i): iface for i, iface in enumerate(detected, 1)}

        chosen: list[DetectedInterface] = []
        for token in args:
            if token in idx_map:
                chosen.append(idx_map[token])
            elif token in name_map:
                chosen.append(name_map[token])
            else:
                self._error(f"Unknown interface: [bold]{token}[/bold]")
                return

        if not chosen:
            return

        # If capture is running, stop it before switching interfaces
        if self.app is not None:
            self._warn("Stopping active capture to switch interfaces")
            await self.app.stop()
            self.app = None

        self.interfaces = [
            InterfaceConfig(name=iface.name, type=iface.type, bindings=iface.bindings)
            for iface in chosen
        ]
        names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)

        # Auto-start capture after selecting interfaces
        self.app = LeethaApp(interfaces=self.interfaces)
        await self.app.start()

        # start() defers capture to start_capture() which checks privileges.
        # If capture didn't actually start, re-exec under sudo.
        if not self.app.capture_engine._workers:
            await self.app.stop()
            self.app = None
            self._warn("Capture requires elevated privileges — re-launching with sudo")
            import os
            import sys
            leetha_bin = os.path.abspath(sys.argv[0])
            iface_args = []
            for iface in self.interfaces:
                iface_args.extend(["-i", iface.name])
            os.execvp("sudo", ["sudo", sys.executable, leetha_bin] + iface_args)
            return  # unreachable — execvp replaces the process

        self._success(f"Capture started on {names}")
        self.console.print()
        self.console.print("  [bold white]What's next?[/bold white]")
        self.console.print()
        next_steps = [
            ("start web",  "Open the browser-based dashboard"),
            ("start cli", "Stream packets with fingerprint reasoning"),
            ("devices",   "View discovered devices"),
            ("alerts",    "View active security alerts"),
        ]
        for cmd, desc in next_steps:
            self.console.print(f"    [bold cyan]{cmd:<12s}[/bold cyan] [dim]{desc}[/dim]")
        self.console.print()

    def _show_interface_hint(self) -> None:
        """Show detected interfaces as a compact quick-pick hint."""
        detected = self._detect_interfaces()
        if not detected:
            self._error("No network interfaces detected")
            return
        parts = []
        for i, iface in enumerate(detected, 1):
            if iface.state == "up":
                parts.append(f"[bold]{i}[/bold]={iface.name}")
            else:
                parts.append(f"[dim]{i}={iface.name}[/dim]")
        self._hint(f"Available: {' '.join(parts)}")
        self._hint("Select with [bold cyan]use interface <name|#>[/bold cyan]")

    async def _ensure_capture(self) -> bool:
        """Start capture if not already running. Returns False if no interfaces."""
        if self.app is not None:
            return True
        if not self.interfaces:
            self._error("No interfaces selected")
            self._show_interface_hint()
            return False
        self.app = LeethaApp(interfaces=self.interfaces)
        await self.app.start()
        if not self.app.capture_engine._workers:
            await self.app.stop()
            self.app = None
            self._warn("Capture requires elevated privileges — re-launching with sudo")
            import os
            import sys
            leetha_bin = os.path.abspath(sys.argv[0])
            iface_args = []
            for iface in self.interfaces:
                iface_args.extend(["-i", iface.name])
            os.execvp("sudo", ["sudo", sys.executable, leetha_bin] + iface_args)
            return False  # unreachable
        names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
        self._success(f"Capture started on {names}")
        return True

    async def _cmd_live(self, args: list[str]) -> None:
        decode = "--decode" in args
        pfilter: str | None = None
        rate: int | None = None

        if "--filter" in args:
            idx = args.index("--filter")
            if idx + 1 < len(args):
                pfilter = args[idx + 1]
            else:
                self._error("[bold]--filter[/bold] requires a value")
                return

        if "--rate" in args:
            idx = args.index("--rate")
            if idx + 1 < len(args):
                try:
                    rate = int(args[idx + 1])
                except ValueError:
                    self._error("[bold]--rate[/bold] requires an integer")
                    return
            else:
                self._error("[bold]--rate[/bold] requires a value")
                return

        if not await self._ensure_capture():
            return

        self._info("Launching live packet stream — [bold]Ctrl+C[/bold] to return")
        try:
            await run_live(decode=decode, packet_filter=pfilter, rate=rate, app=self.app)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        self.console.print()
        self._info("Back in console")

    async def _cmd_web(self, args: list[str]) -> None:
        port = 8080
        host = "0.0.0.0"

        if "--port" in args:
            idx = args.index("--port")
            if idx + 1 < len(args):
                try:
                    port = int(args[idx + 1])
                except ValueError:
                    self._error("[bold]--port[/bold] requires an integer")
                    return
            else:
                self._error("[bold]--port[/bold] requires a value")
                return

        if "--host" in args:
            idx = args.index("--host")
            if idx + 1 < len(args):
                host = args[idx + 1]
            else:
                self._error("[bold]--host[/bold] requires a value")
                return

        if not await self._ensure_capture():
            return

        self._info(f"Web dashboard at [bold cyan]http://{host}:{port}[/bold cyan] — [bold]Ctrl+C[/bold] to return")
        try:
            await run_web_async(host=host, port=port, app=self.app)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        self.console.print()
        self._info("Back in console")

    def _confidence_bar(self, conf: int) -> str:
        """Render a compact confidence indicator."""
        if conf >= 80:
            return f"[bold green]{conf}%[/bold green]"
        elif conf >= 60:
            return f"[green]{conf}%[/green]"
        elif conf >= 40:
            return f"[yellow]{conf}%[/yellow]"
        elif conf >= 20:
            return f"[dark_orange]{conf}%[/dark_orange]"
        else:
            return f"[red]{conf}%[/red]"

    def _get_db(self) -> Database | None:
        """Return the best available DB connection — prefer the app's live connection."""
        if self.app is not None and self.app.db is not None:
            return self.app.db
        return self.db

    async def _cmd_devices(self, args: list[str]) -> None:
        store = self._active_store
        if not store:
            self._error("Store not initialized")
            return

        all_hosts = await store.hosts.find_all(limit=500)
        if not all_hosts:
            self._hint("No devices discovered yet — start a capture first")
            return

        self._section("Discovered Devices", f"{len(all_hosts)} hosts")

        table = Table(
            show_header=True, show_edge=False, pad_edge=True, box=None,
            expand=True, padding=(0, 1),
        )
        table.add_column("Name", style="bold cyan", no_wrap=True, min_width=18)
        table.add_column("MAC", style="blue", no_wrap=True, width=20)
        table.add_column("IPv4", style="white", no_wrap=True, width=16)
        table.add_column("Type", style="white", width=14)
        table.add_column("OS", style="white", width=12)
        table.add_column("Conf", justify="right", width=6)

        for h in all_hosts:
            v = await store.verdicts.find_by_addr(h.hw_addr)
            mac = h.hw_addr
            ip = h.ip_addr
            vendor = v.vendor if v else None
            category = v.category if v else None
            platform = v.platform if v else None
            hostname = v.hostname if v else None
            certainty = v.certainty if v else 0

            # Show randomized MAC indicator
            mac_display = mac
            if h.mac_randomized:
                mac_display = f"{mac} [magenta]R[/magenta]"

            name = hostname or vendor or "[dim]—[/dim]"

            table.add_row(
                name,
                mac_display,
                ip or "[dim]—[/dim]",
                _display_type(category or "unknown"),
                platform or "[dim]—[/dim]",
                self._confidence_bar(certainty),
            )

        self.console.print(table)
        self.console.print()

    _SEVERITY_ICONS: dict[str, str] = {
        "critical": "[bold red]⬤ CRIT[/bold red]",
        "high":     "[red]⬤ HIGH[/red]",
        "warning":  "[yellow]● WARN[/yellow]",
        "low":      "[dim yellow]○ LOW[/dim yellow]",
        "info":     "[blue]○ INFO[/blue]",
    }

    async def _cmd_alerts(self, args: list[str]) -> None:
        store = self._active_store
        if not store:
            self._error("Store not initialized")
            return

        findings = await store.findings.list_active(limit=100)
        if not findings:
            self._success("No active alerts — network looks clean")
            return

        # Count by severity
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.value
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        self._section("Active Alerts", f"{len(findings)} unresolved")

        # Summary badges
        badges = []
        for sev in ("critical", "high", "warning", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count > 0:
                icon = self._SEVERITY_ICONS.get(sev, sev)
                badges.append(f"{icon} {count}")
        if badges:
            self.console.print(f"  {'   '.join(badges)}")
            self.console.print()

        table = Table(
            show_header=True, show_edge=False, pad_edge=True, box=None,
            expand=True, padding=(0, 1),
        )
        table.add_column("Severity", width=12)
        table.add_column("Type", style="cyan", width=16)
        table.add_column("Device", style="blue", width=20)
        table.add_column("Message", min_width=30)
        table.add_column("Time", width=10, style="dim", justify="right")

        for f in findings:
            sev = f.severity.value
            sev_display = self._SEVERITY_ICONS.get(sev, sev.upper())
            time_str = f.timestamp.strftime("%H:%M:%S") if f.timestamp else ""

            table.add_row(
                sev_display,
                f.rule.value,
                f.hw_addr,
                f.message,
                time_str,
            )

        self.console.print(table)
        self.console.print()

    async def _cmd_status(self, args: list[str]) -> None:
        synced = self._count_synced_sources()
        total = len(SourceRegistry().list_sources())

        device_count = 0
        alert_count = 0
        store = self._active_store
        if store:
            device_count = await store.hosts.count()
            alert_count = await store.findings.count_active()

        self._section("System Status")

        # Capture status
        if self.app is not None and self.interfaces:
            iface_names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
            capture_line = f"[green]● active[/green]  {iface_names}"
        elif self.interfaces:
            iface_names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
            capture_line = f"[yellow]○ stopped[/yellow]  {iface_names}"
        else:
            capture_line = "[dim]○ no interfaces selected[/dim]"

        # Sources
        src_color = "green" if synced == total else "yellow"

        # Alerts
        if alert_count == 0:
            alert_line = "[green]0[/green]"
        else:
            alert_line = f"[bold yellow]{alert_count}[/bold yellow]"

        rows = [
            ("Capture",   capture_line),
            ("Sources",   f"[{src_color}]{synced}/{total}[/{src_color}] synced"),
            ("Devices",   f"[bold]{device_count:,}[/bold] discovered"),
            ("Alerts",    f"{alert_line} active"),
            ("Database",  f"[dim]{self.config.db_path}[/dim]"),
            ("Cache",     f"[dim]{self.config.cache_dir}[/dim]"),
        ]

        for label, value in rows:
            self.console.print(f"  [bold white]{label:<12s}[/bold white] {value}")
        self.console.print()

    async def _cmd_start(self, args: list[str]) -> None:
        if args and args[0].lower() == "web":
            await self._cmd_web(args[1:])
            return
        if args and args[0].lower() in ("cli", "live"):
            await self._cmd_live(args[1:])
            return
        if self.app is not None:
            names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces) if self.interfaces else "?"
            self._info(f"Capture already active on {names}")
            return
        if not self.interfaces:
            self._error("No interfaces selected")
            self._show_interface_hint()
            return
        self.app = LeethaApp(interfaces=self.interfaces)
        await self.app.start()
        names = ", ".join(f"[cyan]{i.name}[/cyan]" for i in self.interfaces)
        self._success(f"Capture started on {names}")

    async def _cmd_stop(self, args: list[str]) -> None:
        if self.app is None:
            self._hint("Capture is not running")
            return
        await self.app.stop()
        self.app = None
        self._warn("Capture stopped")

    async def _cmd_clear(self, args: list[str]) -> None:
        os.system("clear")

    async def _cmd_exit(self, args: list[str]) -> None:
        if self.app is not None:
            self._info("Stopping capture")
            await self.app.stop()
            self.app = None
        self._running = False

    _cmd_quit = _cmd_exit

    async def _cmd_probe(self, args: list[str]) -> None:
        """Handle probe commands."""
        from leetha.capture.probes import (
            ProbeDispatcher, PROBE_REGISTRY, get_available_probes,
        )
        from leetha.capture.interfaces import classify_capture_mode

        if not args:
            self._section("Active Probing")
            cmds = [
                ("probe list",               "Show available probe types"),
                ("probe status",             "Show interface probe modes"),
                ("probe enable <interface>", "Enable probing (OPSEC warning)"),
                ("probe disable <interface>","Return to passive mode"),
                ("probe run <iface> <name>", "Execute a specific probe"),
            ]
            for cmd, desc in cmds:
                self.console.print(f"    [bold cyan]{cmd:<30s}[/bold cyan] [dim]{desc}[/dim]")
            self.console.print()
            return

        sub = args[0]

        if sub == "list":
            self._section("Available Probes")

            table = Table(
                show_header=True, show_edge=False, pad_edge=True, box=None,
                expand=False, padding=(0, 2),
            )
            table.add_column("Probe", style="bold cyan", width=22)
            table.add_column("Description", min_width=30)
            table.add_column("Req", width=8, style="dim", justify="center")

            for name, info in PROBE_REGISTRY.items():
                req = "[yellow]L2[/yellow]" if info.requires_l2 else "[dim]—[/dim]"
                table.add_row(name, info.description, req)

            self.console.print(table)
            self.console.print()
            return

        if sub == "status":
            if self.app is None or not self.app.capture_engine.interfaces:
                self._hint("No interfaces configured — start a capture first")
                return

            self._section("Probe Status", "per-interface mode")

            for name, config in self.app.capture_engine.interfaces.items():
                mode = getattr(config, "probe_mode", "passive")
                if mode == "probe-enabled":
                    indicator = "[green]● enabled[/green]"
                else:
                    indicator = "[dim]○ passive[/dim]"
                self.console.print(f"  [cyan]{name:<14s}[/cyan] {indicator}")
            self.console.print()
            return

        if sub == "enable":
            if len(args) < 2:
                self._hint("Usage: [bold cyan]probe enable <interface>[/bold cyan]")
                return
            iface = args[1]
            if self.app is None:
                self._error("Capture not running")
                return
            config = self.app.capture_engine.interfaces.get(iface)
            if not config:
                self._error(f"Interface [bold]{iface}[/bold] not found")
                return
            ip = config.attacker_ip or "unknown"
            self._warn(
                f"Probing on [cyan]{iface}[/cyan] will reveal your IP "
                f"([bold]{ip}[/bold]) on the remote network"
            )
            config.probe_mode = "probe-enabled"
            self._success(f"[cyan]{iface}[/cyan] probe mode: [green]enabled[/green]")
            return

        if sub == "disable":
            if len(args) < 2:
                self._hint("Usage: [bold cyan]probe disable <interface>[/bold cyan]")
                return
            iface = args[1]
            if self.app is None:
                self._error("Capture not running")
                return
            config = self.app.capture_engine.interfaces.get(iface)
            if not config:
                self._error(f"Interface [bold]{iface}[/bold] not found")
                return
            config.probe_mode = "passive"
            self._success(f"[cyan]{iface}[/cyan] probe mode: [dim]passive[/dim]")
            return

        if sub == "run":
            if len(args) < 3:
                self._hint("Usage: [bold cyan]probe run <interface> <probe_name|all>[/bold cyan]")
                return
            iface = args[1]
            probe_name = args[2]
            if self.app is None:
                self._error("Capture not running")
                return
            config = self.app.capture_engine.interfaces.get(iface)
            if not config:
                self._error(f"Interface [bold]{iface}[/bold] not found")
                return

            dispatcher = ProbeDispatcher()

            if probe_name == "all":
                self._info(f"Running all probes on [cyan]{iface}[/cyan]")
                results = await dispatcher.run_all(config)
                for r in results:
                    if r["status"] == "sent":
                        self._success(f"{r['probe']}")
                    else:
                        self._error(f"{r['probe']}: {r.get('error', 'unknown')}")
            else:
                try:
                    result = await dispatcher.run_probe(probe_name, config)
                    self._success(result.get("message", "Probe sent"))
                except ValueError as e:
                    self._error(str(e))
            return

        self._error(f"Unknown subcommand: [bold]{sub}[/bold]")
        self._hint("Available: [bold cyan]list[/bold cyan], [bold cyan]status[/bold cyan], [bold cyan]enable[/bold cyan], [bold cyan]disable[/bold cyan], [bold cyan]run[/bold cyan]")


# Entry point


async def run_console(interfaces: list | None = None, initial_command: str | None = None) -> None:
    """Entry point for interactive console mode."""
    console = LeethaConsole(interfaces=interfaces, initial_command=initial_command)
    await console.run()
