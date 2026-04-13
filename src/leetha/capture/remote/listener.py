"""Standalone WebSocket listener for remote sensor connections.

Runs independently of the FastAPI web server so sensors can connect
in console, live, and web modes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
from pathlib import Path

log = logging.getLogger(__name__)

_server_task: asyncio.Task | None = None
_heartbeat_task: asyncio.Task | None = None
_ws_server = None


async def _emit_sensor_finding(app, rule: str, severity: str, sensor_name: str, message: str):
    """Emit a finding for sensor connect/disconnect events."""
    try:
        from leetha.store.models import Finding, FindingRule, AlertSeverity
        finding = Finding(
            hw_addr=f"sensor:{sensor_name}",
            rule=FindingRule(rule),
            severity=AlertSeverity(severity),
            message=message,
        )
        if hasattr(app, 'store') and app.store:
            await app.store.findings.add(finding)
    except Exception as exc:
        log.debug("failed to emit sensor finding: %s", exc)


async def send_control(session, message: dict) -> bool:
    """Send a JSON control message to a sensor's websocket."""
    if session.websocket is None:
        return False
    try:
        await session.websocket.send(json.dumps(message))
        return True
    except Exception as exc:
        log.debug("failed to send control to %s: %s", session.name, exc)
        return False


async def start_sensor_listener(
    app,
    host: str = "0.0.0.0",
    port: int = 8443,
) -> None:
    """Start the WebSocket sensor listener in the background."""
    global _server_task, _heartbeat_task, _ws_server

    if _server_task and not _server_task.done():
        log.debug("sensor listener already running")
        return

    try:
        import websockets
        from websockets.asyncio.server import serve
    except ImportError:
        log.warning("websockets not installed — remote sensor listener disabled")
        return

    manager = app._remote_sensor_manager
    ca_dir = Path(app.config.data_dir) / "ca"

    # Load sensor config store
    from leetha.capture.remote.config import SensorConfigStore
    config_store = SensorConfigStore(Path(app.config.data_dir) / "sensor_config.json")

    async def handle_sensor(websocket):
        from scapy.layers.l2 import Ether

        # Extract sensor name from query params
        path = websocket.request.path if hasattr(websocket, 'request') else ""
        params = {}
        if "?" in path:
            query = path.split("?", 1)[1]
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v

        sensor_name = params.get("name")
        if not sensor_name:
            await websocket.close(1008, "Sensor name required")
            return

        if manager.is_revoked(sensor_name, ca_dir):
            await websocket.close(1008, "Certificate revoked")
            return

        try:
            session = manager.register(sensor_name, str(websocket.remote_address[0]))
        except ValueError:
            await websocket.close(1008, "Sensor already connected")
            return

        # Store websocket reference for control messages
        session.websocket = websocket

        log.info("remote sensor connected: %s from %s", sensor_name, websocket.remote_address[0])
        await _emit_sensor_finding(
            app, "sensor_connect", "info", sensor_name,
            f"Remote sensor connected: {sensor_name} from {websocket.remote_address[0]}"
        )

        try:
            async for message in websocket:
                # Text messages = control/discovery (JSON)
                if isinstance(message, str):
                    try:
                        payload = json.loads(message)
                        msg_type = payload.get("type")

                        if msg_type == "discovery":
                            ifaces = payload.get("interfaces", [])
                            session.set_discovered_interfaces(ifaces)
                            log.info(
                                "sensor %s reported %d interfaces",
                                sensor_name, len(ifaces),
                            )
                            # Re-send saved interface selection if available
                            saved = config_store.load_interfaces(sensor_name)
                            if saved:
                                await send_control(session, {
                                    "type": "capture_start",
                                    "interfaces": saved,
                                })
                                session.set_state("capturing", saved)
                                log.info("sensor %s: restored capture on %s", sensor_name, saved)

                        elif msg_type == "heartbeat":
                            iface_stats = payload.get("stats", {})
                            session.update_heartbeat(iface_stats)

                        elif msg_type == "capture_status":
                            state = payload.get("state", "idle")
                            ifaces = payload.get("interfaces", [])
                            session.set_state(state, ifaces)
                            log.info("sensor %s: state=%s interfaces=%s", sensor_name, state, ifaces)

                        elif msg_type == "capture_error":
                            iface = payload.get("interface", "unknown")
                            error = payload.get("error", "unknown error")
                            session.set_interface_error(iface, error)
                            log.warning("sensor %s: capture error on %s: %s", sensor_name, iface, error)

                    except Exception:
                        pass
                    continue

                # Binary messages = packet frames
                try:
                    frames = session.feed(message)
                except Exception:
                    log.debug("sensor %s: malformed frame data, skipping", sensor_name)
                    continue

                for frame in frames:
                    try:
                        pkt = Ether(frame.packet)
                        iface_label = f"remote:{sensor_name}"
                        # Route through _ingest() so dedup filters
                        # (ip_observed, banner) are applied the same
                        # way as local captures.
                        app.capture_engine._ingest(pkt, iface_label)
                    except Exception:
                        pass
        except Exception as exc:
            log.warning("sensor %s connection error: %s", sensor_name, exc)
        finally:
            session.websocket = None
            manager.unregister(sensor_name)
            log.info("remote sensor disconnected: %s", sensor_name)
            await _emit_sensor_finding(
                app, "sensor_disconnect", "warning", sensor_name,
                f"Remote sensor disconnected: {sensor_name}"
            )

    async def _heartbeat_monitor():
        """Periodically check for stale sensors."""
        while True:
            await asyncio.sleep(30)
            stale = manager.get_stale_sensors(timeout=90)
            for s in stale:
                log.warning("sensor %s: no heartbeat for >90s", s.name)
                await _emit_sensor_finding(
                    app, "sensor_disconnect", "warning", s.name,
                    f"Remote sensor unresponsive: {s.name} (no heartbeat)"
                )

    async def _run_server():
        global _ws_server
        try:
            from leetha.capture.remote.ca import ensure_server_cert, CANotInitialized
            try:
                server_cert, server_key = ensure_server_cert(ca_dir)
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(str(server_cert), str(server_key))
                ssl_ctx.load_verify_locations(str(ca_dir / "ca.crt"))
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            except CANotInitialized:
                log.warning("CA not initialized — sensor listener disabled (build a sensor first)")
                return

            _ws_server = await serve(
                handle_sensor,
                host,
                port,
                ssl=ssl_ctx,
                logger=log,
                ping_interval=None,
            )
            log.info("sensor listener started on %s:%d (mTLS)", host, port)
            await _ws_server.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e):
                log.info("sensor listener port %d in use (web server likely running) — skipping", port)
            else:
                log.warning("sensor listener failed: %s", e)
        except Exception as e:
            log.warning("sensor listener error: %s", e)

    _server_task = asyncio.create_task(_run_server())
    _heartbeat_task = asyncio.create_task(_heartbeat_monitor())


async def stop_sensor_listener() -> None:
    """Stop the sensor listener."""
    global _server_task, _heartbeat_task, _ws_server
    if _ws_server:
        _ws_server.close()
        _ws_server = None
    if _heartbeat_task and not _heartbeat_task.done():
        _heartbeat_task.cancel()
        try:
            await _heartbeat_task
        except asyncio.CancelledError:
            pass
        _heartbeat_task = None
    if _server_task and not _server_task.done():
        _server_task.cancel()
        try:
            await _server_task
        except asyncio.CancelledError:
            pass
        _server_task = None
