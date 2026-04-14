"""SSH-based ad-hoc remote packet capture."""
from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_SAFE_IFACE = re.compile(r'^[a-zA-Z0-9._-]+$')


def _validate_interface(interface: str) -> str:
    """Validate interface name to prevent shell injection."""
    if not _SAFE_IFACE.match(interface):
        raise ValueError(f"Invalid interface name: {interface!r}")
    return interface


@dataclass
class SSHCaptureConfig:
    user: str
    host: str
    port: int = 22
    key_path: str | None = None
    interface: str = "any"


def parse_ssh_url(url: str) -> SSHCaptureConfig:
    if not url.startswith("ssh://"):
        raise ValueError("Remote URL must start with ssh://")
    parsed = urlparse(url)
    if not parsed.username:
        raise ValueError("SSH URL must include a user (ssh://user@host)")
    return SSHCaptureConfig(
        user=parsed.username,
        host=parsed.hostname or "",
        port=parsed.port or 22,
    )


def build_capture_commands(interface: str) -> list[str]:
    interface = _validate_interface(interface)
    return [
        f"tcpdump -U -w - -i {interface} 2>/dev/null",
        f"dumpcap -i {interface} -w - 2>/dev/null",
        f"tshark -i {interface} -w - 2>/dev/null",
    ]


async def ssh_capture(
    config: SSHCaptureConfig,
    packet_callback,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Connect via SSH and stream pcap data from the remote host.

    Args:
        config: SSH connection and capture parameters.
        packet_callback: Async callable receiving (raw_bytes, interface_label).
            The raw_bytes are pcap-formatted output from tcpdump.
        stop_event: Optional event to signal capture should stop.
    """
    import asyncssh

    # Use system known_hosts for host key verification when available;
    # fall back to None (accept any key) only if the file doesn't exist.
    known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
    connect_kwargs: dict = {
        "host": config.host,
        "port": config.port,
        "username": config.user,
        "known_hosts": known_hosts_path if os.path.exists(known_hosts_path) else None,
    }
    if config.key_path:
        connect_kwargs["client_keys"] = [config.key_path]

    _validate_interface(config.interface)
    commands = build_capture_commands(config.interface)
    interface_label = f"ssh:{config.user}@{config.host}:{config.interface}"

    async with asyncssh.connect(**connect_kwargs) as conn:
        # Try each capture tool in order
        for cmd in commands:
            try:
                log.info("trying remote capture: %s", cmd)
                proc = await conn.create_process(cmd)

                # Read pcap stream
                while True:
                    if stop_event and stop_event.is_set():
                        proc.terminate()
                        break
                    chunk = await asyncio.wait_for(
                        proc.stdout.read(65536), timeout=5.0
                    )
                    if not chunk:
                        break
                    await packet_callback(chunk, interface_label)

                return  # Successful capture ended normally

            except (asyncssh.ProcessError, OSError) as e:
                log.debug("capture tool failed: %s — %s", cmd, e)
                continue

        raise RuntimeError(
            "No capture tool found on remote host. "
            "Install tcpdump, dumpcap, or tshark."
        )
