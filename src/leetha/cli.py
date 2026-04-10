import argparse
import asyncio
import os

import sys


def parse_interface_arg(spec: str) -> tuple[str, str, str | None]:
    """Parse 'name[:type[:label]]' interface specification.

    Returns (name, type, label).
    """
    parts = spec.split(":", maxsplit=2)
    name = parts[0]
    itype = parts[1] if len(parts) > 1 else "local"
    label = parts[2] if len(parts) > 2 else None
    return name, itype, label


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leetha",
        description="Passive network device discovery and fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  leetha                          Interactive console
  leetha --web                    Web dashboard (select interfaces in UI)
  leetha --web -i eth0            Web dashboard on specific interface
  leetha -i eth0                  Console on specific interface
  leetha -i eth0 -i wlan0         Multi-interface capture
  leetha sync                     Update fingerprint databases

console commands:
  list interfaces                Show detected network interfaces
  use interface 1 3              Select interfaces + start capture
  start web                      Launch web dashboard
  start cli                      Launch live packet stream
""",
    )
    parser.add_argument(
        "-i", "--interface",
        action="append",
        default=[],
        help="Network interface (repeatable, format: name[:type[:label]])",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Show live packet stream with fingerprint reasoning",
    )
    parser.add_argument(
        "--decode",
        action="store_true",
        help="Full protocol decode in --live mode",
    )
    parser.add_argument(
        "--filter",
        help="Filter packets (protocol name or mac=XX:XX:XX)",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=None,
        help="Max events/sec displayed in --live mode (default: unlimited)",
    )
    parser.add_argument(
        "--on",
        help="Filter display to specific interface",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        dest="web_only",
        help="Launch web UI directly (skip interactive console)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Web UI bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Web UI port (default: 8080)",
    )
    parser.add_argument(
        "--auth", action="store_true", default=None, dest="force_auth",
        help="Force API authentication on (even on localhost)",
    )
    parser.add_argument(
        "--no-auth", action="store_false", dest="force_auth",
        help="Force API authentication off (even on 0.0.0.0)",
    )
    parser.add_argument(
        "--probe", action="store_true", default=False,
        help="Enable active probing alongside passive capture",
    )
    parser.add_argument(
        "--socket",
        default=None,
        metavar="PATH",
        help="Listen on a Unix domain socket for event streaming (e.g. /tmp/leetha.sock)",
    )
    parser.add_argument(
        "--service",
        action="store_true",
        default=False,
        help="Service mode: web UI + auto-capture on saved interfaces, no prompts",
    )

    sub = parser.add_subparsers(dest="command")

    sync_parser = sub.add_parser("sync", help="Update fingerprint databases")
    sync_parser.add_argument(
        "--list",
        action="store_true",
        dest="list_sources",
        help="Show available sources and status",
    )
    sync_parser.add_argument(
        "--source",
        help="Update specific source by name",
    )

    # Override subcommand
    override_parser = sub.add_parser("override", help="Manage manual device overrides")
    override_sub = override_parser.add_subparsers(dest="override_action")

    override_sub.add_parser("list", help="List all devices with overrides")

    override_show = override_sub.add_parser("show", help="Show override for a device")
    override_show.add_argument("mac", help="Device MAC address")

    override_set = override_sub.add_parser("set", help="Set override for a device")
    override_set.add_argument("mac", help="Device MAC address")
    override_set.add_argument("--device-type", dest="device_type", help="Device type override")
    override_set.add_argument("--manufacturer", help="Manufacturer override")
    override_set.add_argument("--os-family", dest="os_family", help="OS family override")
    override_set.add_argument("--os-version", dest="os_version", help="OS version override")
    override_set.add_argument("--model", help="Device model override")
    override_set.add_argument("--hostname", help="Hostname override")
    override_set.add_argument("--connection-type", dest="connection_type", help="Connection type (wired/wireless)")
    override_set.add_argument("--disposition", help="Disposition (new/known/suspicious)")
    override_set.add_argument("--notes", help="Analyst notes")

    override_clear = override_sub.add_parser("clear", help="Clear override for a device")
    override_clear.add_argument("mac", help="Device MAC address")

    # Patterns subcommand
    patterns_parser = sub.add_parser("patterns", help="Manage custom fingerprint patterns")
    patterns_sub = patterns_parser.add_subparsers(dest="patterns_action")

    patterns_sub.add_parser("list", help="List all custom patterns")

    patterns_add = patterns_sub.add_parser("add", help="Add a custom pattern")
    patterns_add.add_argument("pattern_type", choices=["hostname", "dhcp_opt55", "dhcp_opt60", "mac_prefix"])
    patterns_add.add_argument("--pattern", help="Regex pattern (hostname/dhcp_opt60)")
    patterns_add.add_argument("--key", help="Option list key (dhcp_opt55) or MAC prefix (mac_prefix)")
    patterns_add.add_argument("--device-type", dest="device_type", help="Device type")
    patterns_add.add_argument("--manufacturer", help="Manufacturer")
    patterns_add.add_argument("--os-family", dest="os_family", help="OS family")
    patterns_add.add_argument("--confidence", type=int, default=80, help="Confidence (0-100)")

    patterns_remove = patterns_sub.add_parser("remove", help="Remove a custom pattern")
    patterns_remove.add_argument("pattern_type", help="Pattern type (hostname, dhcp_opt55, etc.)")
    patterns_remove.add_argument("index", help="Pattern index to remove")

    patterns_sub.add_parser("export", help="Export custom patterns to stdout")

    patterns_import = patterns_sub.add_parser("import", help="Import patterns from stdin")
    patterns_import.add_argument("file", nargs="?", help="Pattern file to import (default: stdin)")

    # Validate subcommand
    validate_parser = sub.add_parser("validate", help="Validate synced data quality")
    validate_parser.add_argument("--verbose", action="store_true", help="Show per-device details")
    validate_parser.add_argument("--check", choices=["oui", "manufacturer", "stale"], help="Run specific check only")

    # Probe subcommand
    probe_parser = sub.add_parser("probe", help="Active probe a host:port")
    probe_parser.add_argument("target", help="host:port to probe (e.g. 192.168.1.1:22)")

    # Interfaces subcommand
    interfaces_parser = sub.add_parser("interfaces", help="Manage capture interfaces")
    interfaces_sub = interfaces_parser.add_subparsers(dest="interfaces_action")
    interfaces_sub.add_parser("list", help="List detected interfaces")
    iface_add = interfaces_sub.add_parser("add", help="Add interface to saved config")
    iface_add.add_argument("spec", help="Interface spec: name[:type[:label]]")
    iface_remove = interfaces_sub.add_parser("remove", help="Remove interface from saved config")
    iface_remove.add_argument("name", help="Interface name to remove")
    iface_show = interfaces_sub.add_parser("show", help="Show interface details")
    iface_show.add_argument("name", help="Interface name")

    # Trust subcommand
    trust_parser = sub.add_parser("trust", help="Manage trusted MAC/IP bindings")
    trust_sub = trust_parser.add_subparsers(dest="trust_action")
    trust_sub.add_parser("list", help="List all trusted bindings")
    trust_add = trust_sub.add_parser("add", help="Pin a MAC/IP binding")
    trust_add.add_argument("mac", help="MAC address to trust")
    trust_add.add_argument("ip", help="IP address to bind")
    trust_remove = trust_sub.add_parser("remove", help="Remove a trusted binding")
    trust_remove.add_argument("mac", help="MAC address to unpin")

    # Auth subcommand
    auth_parser = sub.add_parser("auth", help="Manage API authentication tokens")
    auth_sub = auth_parser.add_subparsers(dest="auth_action")
    auth_sub.add_parser("show-token", help="Display admin token from ~/.leetha/admin-token")
    auth_sub.add_parser("reset-token", help="Regenerate admin token (invalidates old one)")
    auth_create = auth_sub.add_parser("create-token", help="Create a new API token")
    auth_create.add_argument("role", choices=["admin", "analyst"], help="Token role")
    auth_create.add_argument("--label", help="Optional label for the token")
    auth_sub.add_parser("list-tokens", help="List all tokens")
    auth_revoke = auth_sub.add_parser("revoke-token", help="Revoke a token by ID")
    auth_revoke.add_argument("id", type=int, help="Token ID to revoke")

    # Import subcommand
    import_parser = sub.add_parser("import", help="Import PCAP files for analysis")
    import_parser.add_argument("files", nargs="+", help="PCAP/PCAPNG/CAP files to import")
    import_parser.add_argument(
        "--max-size", type=int, default=500,
        help="Max file size in MB (default: 500)",
    )

    return parser


def _needs_capture(args: argparse.Namespace) -> bool:
    """Return True if the selected mode requires packet capture privileges."""
    return args.command not in ("sync", "override", "patterns", "validate", "probe", "interfaces", "trust", "auth", "import")


def _has_capture_privilege() -> bool:
    """Return True if the process can open a raw packet socket."""
    from leetha.platform import has_capture_privilege
    return has_capture_privilege()


def _escalate_privileges():
    """Re-exec the current command with elevated privileges."""
    from leetha.platform import escalate_privileges
    escalate_privileges()


def handle_probe(args):
    """One-shot active probe."""
    import json
    from leetha.probe.engine import ProbeEngine

    host, _, port_str = args.target.rpartition(":")
    if not host or not port_str:
        print("Usage: leetha probe <host:port>")
        return

    port = int(port_str)
    engine = ProbeEngine()
    engine.load_plugins()
    result = engine.probe(host, port)

    if result:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"No service identified on {host}:{port}")


async def _run_trust(args):
    """Helper to run trust subcommand with a database connection."""
    from leetha.cli_trust import run_trust
    from leetha.config import get_config
    from leetha.store.database import Database

    config = get_config()
    db = Database(config.db_path)
    await db.initialize()
    try:
        await run_trust(args, db)
    finally:
        await db.close()


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Only escalate privileges immediately for live mode (needs capture from
    # the start).  Web and console modes can start without privileges and
    # defer capture until the user selects an interface.
    if args.live and not _has_capture_privilege():
        _escalate_privileges()

    if args.command == "interfaces":
        from leetha.capture.interfaces import detect_interfaces, get_routes, enrich_interfaces
        from leetha.capture.interfaces import load_interface_config, save_interface_config
        from leetha.config import get_config
        config = get_config()

        action = getattr(args, "interfaces_action", None)
        if action == "list" or action is None:
            detected = detect_interfaces(include_down=True)
            routes = get_routes()
            enrich_interfaces(detected, routes)
            saved = load_interface_config(config.data_dir)
            saved_names = {s.name for s in saved}
            for iface in detected:
                status = "[SELECTED]" if iface.name in saved_names else ""
                ips = ", ".join(b.address for b in iface.bindings)
                print(f"  {iface.name:15s} {iface.state:5s} {iface.type:10s} {ips:30s} {status}")
        return

    if args.command == "sync":
        from leetha.sync import run_sync
        asyncio.run(run_sync(
            list_sources=args.list_sources,
            source=args.source,
        ))
        return
    elif args.command == "override":
        from leetha.cli_override import run_override
        asyncio.run(run_override(args))
        return
    elif args.command == "patterns":
        from leetha.cli_patterns import run_patterns
        asyncio.run(run_patterns(args))
        return
    elif args.command == "validate":
        from leetha.cli_validate import run_validate
        asyncio.run(run_validate(args))
        return
    elif args.command == "probe":
        handle_probe(args)
        return
    elif args.command == "trust":
        asyncio.run(_run_trust(args))
        return
    elif args.command == "auth":
        from leetha.cli_auth import run_auth
        asyncio.run(run_auth(args))
        return
    elif args.command == "import":
        from leetha.cli_import import run_import
        asyncio.run(run_import(args))
        return
    # Apply optional flags to config
    from leetha.config import get_config
    config = get_config()
    if getattr(args, "probe", False):
        config.probe_enabled = True
    if getattr(args, "socket", None):
        config.socket_path = args.socket

    # Build InterfaceConfig list from all -i args
    from leetha.capture.interfaces import InterfaceConfig
    iface_configs = []
    for spec in args.interface:
        name, itype, label = parse_interface_arg(spec)
        iface_configs.append(InterfaceConfig(name=name, type=itype, label=label))

    if args.service:
        import signal

        def _fast_exit(signum, frame):
            print("\n\033[33m[*] Shutting down Leetha...\033[0m")
            sys.stdout.flush()
            import threading
            def _force():
                import time
                time.sleep(3)
                os._exit(1)
            threading.Thread(target=_force, daemon=True).start()

        signal.signal(signal.SIGINT, _fast_exit)
        signal.signal(signal.SIGTERM, _fast_exit)

        # Load saved interfaces for auto-capture, but only if the user
        # didn't explicitly specify interfaces with -i
        if not iface_configs:
            from leetha.capture.interfaces import load_interface_config
            from leetha.config import get_config
            config = get_config()
            saved = load_interface_config(config.data_dir)
            if saved:
                iface_configs = saved

        from leetha.ui.web.app import run_web
        try:
            run_web(
                interfaces=iface_configs or None,
                host=args.host,
                port=args.port,
                force_auth=args.force_auth,
            )
        except (KeyboardInterrupt, SystemExit):
            print("\033[32m[+] Leetha stopped\033[0m")
        return

    if args.live:
        from leetha.ui.live import run_live
        asyncio.run(run_live(
            interfaces=iface_configs or None,
            decode=args.decode,
            packet_filter=args.filter,
            rate=args.rate,
        ))
    elif args.web_only:
        import signal

        def _fast_exit(signum, frame):
            print("\n\033[33m[*] Shutting down Leetha...\033[0m")
            sys.stdout.flush()
            # Force exit after 3 seconds if graceful shutdown hangs
            import threading
            def _force():
                import time
                time.sleep(3)
                print("\033[31m[!] Forced exit\033[0m")
                os._exit(1)
            threading.Thread(target=_force, daemon=True).start()

        signal.signal(signal.SIGINT, _fast_exit)
        signal.signal(signal.SIGTERM, _fast_exit)

        from leetha.ui.web.app import run_web
        try:
            run_web(
                interfaces=iface_configs or None,
                host=args.host,
                port=args.port,
                force_auth=args.force_auth,
            )
        except (KeyboardInterrupt, SystemExit):
            print("\033[32m[+] Leetha stopped\033[0m")
    else:
        from leetha.console import run_console
        try:
            asyncio.run(run_console(interfaces=iface_configs or None))
        except KeyboardInterrupt:
            print("\n\033[33m[*] Leetha stopped\033[0m")


if __name__ == "__main__":
    main()
