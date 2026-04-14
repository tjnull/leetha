"""Device-related API routes."""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


def _get_app():
    from leetha.ui.web.app import app_instance
    return app_instance


def _get_helpers():
    from leetha.ui.web.app import (
        _validate_mac, _sanitize_hostname, _build_device_dict,
    )
    return _validate_mac, _sanitize_hostname, _build_device_dict



async def _get_arp_history_from_sightings(mac: str | None = None, ip: str | None = None) -> list:
    """Derive ARP history from sightings table."""
    app_instance = _get_app()
    history = []
    try:
        if mac:
            cursor = await app_instance.store.connection.execute(
                "SELECT hw_addr, payload, timestamp FROM sightings "
                "WHERE hw_addr = ? AND source = 'arp' ORDER BY timestamp DESC LIMIT 100",
                (mac,),
            )
        elif ip:
            cursor = await app_instance.store.connection.execute(
                "SELECT hw_addr, payload, timestamp FROM sightings "
                "WHERE source = 'arp' ORDER BY timestamp DESC LIMIT 500",
            )
        else:
            return []
        rows = await cursor.fetchall()
        for r in rows:
            payload = json.loads(r[1]) if isinstance(r[1], str) else (r[1] or {})
            src_ip = payload.get("src_ip") or payload.get("sender_ip") or ""
            if ip and src_ip != ip:
                continue
            history.append({
                "mac": r[0],
                "ip": src_ip,
                "first_seen": r[2],
                "last_seen": r[2],
            })
    except Exception:
        pass
    # Deduplicate by mac+ip, keeping earliest first_seen and latest last_seen
    merged: dict[tuple, dict] = {}
    for h in history:
        key = (h["mac"], h["ip"])
        if key in merged:
            merged[key]["last_seen"] = max(merged[key]["last_seen"], h["last_seen"])
            merged[key]["first_seen"] = min(merged[key]["first_seen"], h["first_seen"])
        else:
            merged[key] = h
    return list(merged.values())


@router.get("/api/devices")
async def api_devices(
    page: int = 1,
    per_page: int = 50,
    sort: str = "last_seen",
    order: str = "desc",
    q: str | None = None,
    manufacturer: str | None = None,
    device_type: str | None = None,
    os_family: str | None = None,
    alert_status: str | None = None,
    interface: str | None = None,
    confidence_min: int | None = None,
    raw: bool = False,
):
    """Paginated, filtered, sorted device list."""
    per_page = min(max(per_page, 1), 500)
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    devices, total = await app_instance.store.verdicts.list_devices(
        page=page, per_page=per_page, sort=sort, order=order,
        q=q, manufacturer=manufacturer, device_type=device_type,
        os_family=os_family, alert_status=alert_status,
        interface=interface, confidence_min=confidence_min,
    )

    # Sanitize hostnames and reject vendor-mismatched forwarded mDNS names
    from leetha.evidence.hostname import hostname_matches_vendor
    for d in devices:
        d["hostname"] = _sanitize_hostname(d.get("hostname"))
        if d.get("hostname") and not hostname_matches_vendor(d["hostname"], d.get("manufacturer")):
            d["hostname"] = None

    return {
        "devices": devices,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/api/devices/export")
async def export_devices(
    format: str = "csv",
    q: str | None = None,
    manufacturer: str | None = None,
    device_type: str | None = None,
    os_family: str | None = None,
    alert_status: str | None = None,
):
    """Export devices as CSV or JSON, respecting current filters."""
    from fastapi import HTTPException
    from fastapi.responses import Response, JSONResponse
    import csv
    import io

    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    # Build device dicts from ALL hosts (including those without verdicts)
    host_count = await app_instance.store.hosts.count()
    hosts = await app_instance.store.hosts.find_all(limit=max(host_count, 10000))
    all_devices = []
    for h in hosts:
        v = await app_instance.store.verdicts.find_by_addr(h.hw_addr)
        ovr = await app_instance.store.overrides.find_by_addr(h.hw_addr)
        all_devices.append(_build_device_dict(v, h, ovr))

    # Apply filters
    if q:
        q_lower = q.lower()
        all_devices = [
            d for d in all_devices
            if q_lower in (d.get("mac") or "").lower()
            or q_lower in (d.get("ip_v4") or "").lower()
            or q_lower in (d.get("hostname") or "").lower()
            or q_lower in (d.get("manufacturer") or "").lower()
        ]
    if manufacturer:
        all_devices = [d for d in all_devices if d.get("manufacturer") == manufacturer]
    if device_type:
        all_devices = [d for d in all_devices if d.get("device_type") == device_type]
    if os_family:
        all_devices = [d for d in all_devices if d.get("os_family") == os_family]
    if alert_status:
        all_devices = [d for d in all_devices if d.get("alert_status") == alert_status]

    csv_fields = [
        "mac", "ip_v4", "ip_v6", "manufacturer", "device_type",
        "os_family", "os_version", "hostname", "confidence",
        "first_seen", "last_seen", "alert_status",
    ]

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=csv_fields)
        writer.writeheader()
        for d in all_devices:
            writer.writerow({k: d.get(k) for k in csv_fields})

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices.csv"},
        )

    elif format == "json":
        export_data = []
        for d in all_devices:
            dd = dict(d)
            dd.pop("raw_evidence", None)
            export_data.append(dd)
        return JSONResponse(
            content=export_data,
            headers={"Content-Disposition": "attachment; filename=devices.json"},
        )

    else:
        raise HTTPException(400, "Invalid format. Use csv or json.")


@router.post("/api/devices/bulk")
async def bulk_device_action(request: Request):
    """Bulk update device status."""
    from fastapi import HTTPException

    app_instance = _get_app()

    data = await request.json()
    macs = data.get("macs", [])
    action = data.get("action")  # "mark_known" | "mark_suspicious"

    if action == "mark_known":
        status = "known"
    elif action == "mark_suspicious":
        status = "suspicious"
    else:
        raise HTTPException(400, "Invalid action. Use mark_known or mark_suspicious.")

    updated = 0
    for mac in macs:
        host = await app_instance.store.hosts.find_by_addr(mac)
        if host:
            host.disposition = status
            await app_instance.store.hosts.upsert(host)
            updated += 1

    return {"status": "ok", "updated": updated}


@router.get("/api/devices/{mac}")
async def api_device(mac: str):
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        return JSONResponse(status_code=404, content={"error": "Device not found"})
    override = await app_instance.store.overrides.find_by_addr(mac)
    device = _build_device_dict(verdict, host, override)
    device["hostname"] = _sanitize_hostname(device.get("hostname"))
    # Reject forwarded mDNS hostnames that belong to a different vendor
    from leetha.evidence.hostname import hostname_matches_vendor
    if device.get("hostname") and not hostname_matches_vendor(device["hostname"], device.get("manufacturer")):
        device["hostname"] = None
    # Include sightings as observations for compatibility
    try:
        sightings = await app_instance.store.sightings.for_host(mac)
    except Exception:
        sightings = []
    # Fetch all known IPs from ARP history (multiple VLANs/interfaces)
    known_ips = []
    try:
        arp_history = await app_instance.db.get_arp_history_for_mac(mac)
        known_ips = [
            {"ip": e["ip"], "interface": e["interface"],
             "last_seen": e["last_seen"], "packet_count": e["packet_count"]}
            for e in arp_history
        ]
    except Exception:
        pass

    if known_ips:
        device["known_ips"] = known_ips

    return {
        "device": device,
        "observations": [
            {
                "source_type": s.source,
                "raw_data": json.dumps(s.payload) if isinstance(s.payload, dict) else str(s.payload),
                "match_result": json.dumps(s.analysis) if isinstance(s.analysis, dict) else str(s.analysis),
                "confidence": int(s.certainty * 100) if s.certainty <= 1 else int(s.certainty),
                "timestamp": s.timestamp.isoformat() if s.timestamp else None,
            }
            for s in sightings
        ],
    }


@router.get("/api/devices/{mac}/override")
async def get_device_override(mac: str):
    """Get the manual override for a device."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    override = await app_instance.store.overrides.find_by_addr(mac)
    return {"mac": mac, "override": override}


@router.put("/api/devices/{mac}/override")
async def set_device_override(mac: str, request: Request):
    """Set or update the manual override for a device."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})

    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        return JSONResponse(status_code=404, content={"error": "Device not found"})

    override_data = await request.json()
    from leetha.store.overrides import ALLOWED_FIELDS
    filtered = {k: v for k, v in override_data.items() if k in ALLOWED_FIELDS}

    if not filtered:
        return JSONResponse(status_code=400, content={"error": "No valid override fields provided"})

    result = await app_instance.store.overrides.upsert(mac, filtered)

    # Sync disposition to Host if overridden
    if "disposition" in filtered and filtered["disposition"] and host:
        host.disposition = filtered["disposition"]
        await app_instance.store.hosts.upsert(host)

    return {"status": "ok", "mac": mac, "override": result}


@router.delete("/api/devices/{mac}/override")
async def delete_device_override(mac: str):
    """Clear the manual override for a device."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})

    override = await app_instance.store.overrides.find_by_addr(mac)
    if override and override.get("disposition"):
        host = await app_instance.store.hosts.find_by_addr(mac)
        if host and host.disposition != "self":
            host.disposition = "new"
            await app_instance.store.hosts.upsert(host)

    await app_instance.store.overrides.delete(mac)
    return {"status": "ok", "mac": mac}


@router.get("/api/devices/{mac}/arp-history")
async def api_device_arp_history(mac: str):
    """Get ARP history for a device from sightings."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    history = await _get_arp_history_from_sightings(mac=mac.lower())
    return {"history": history}


@router.get("/api/devices/{mac}/detail")
async def get_device_detail(mac: str):
    """Full device info + evidence breakdown."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    from fastapi import HTTPException

    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        raise HTTPException(404, "Device not found")

    override = await app_instance.store.overrides.find_by_addr(mac)
    device = _build_device_dict(verdict, host, override)
    device["hostname"] = _sanitize_hostname(device.get("hostname"))
    evidence = device.get("raw_evidence", {})

    return {
        "device": device,
        "evidence": evidence,
    }


@router.get("/api/devices/{mac}/coverage")
async def get_device_coverage(mac: str):
    """Diagnostic: what evidence sources have been observed for this device."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    if not verdict and not host:
        return JSONResponse(status_code=404, content={"error": "Device not found"})

    override = await app_instance.store.overrides.find_by_addr(mac)
    device = _build_device_dict(verdict, host, override)

    # Get observation source types from sightings
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT source, COUNT(*) as cnt, MAX(timestamp) as last "
            "FROM sightings WHERE hw_addr = ? GROUP BY source ORDER BY cnt DESC",
            (mac,),
        )
        rows = await cursor.fetchall()
        observed_sources = {r[0]: {"count": r[1], "last_seen": r[2]} for r in rows}
    except Exception:
        observed_sources = {}

    # Define all possible sources and what they provide
    ALL_SOURCES = {
        "arp": {"provides": ["MAC-IP binding"], "passive": True, "layer": "L2"},
        "tcp_syn": {"provides": ["OS family (TTL)", "TCP stack fingerprint"], "passive": True, "layer": "L3"},
        "dhcpv4": {"provides": ["Hostname", "Vendor class", "OS fingerprint", "Device type"], "passive": True, "layer": "L3"},
        "dhcpv6": {"provides": ["IPv6 fingerprint", "Enterprise ID", "Vendor class"], "passive": True, "layer": "L3"},
        "mdns": {"provides": ["Device model", "Friendly name", "Services", "Manufacturer"], "passive": True, "layer": "L3 multicast"},
        "ssdp": {"provides": ["Manufacturer", "Model", "Firmware", "Device description"], "passive": True, "layer": "L3 multicast"},
        "dns": {"provides": ["Hostname patterns", "Cloud services used"], "passive": True, "layer": "L3"},
        "tls": {"provides": ["JA3/JA4 fingerprint", "SNI (services used)"], "passive": True, "layer": "L4"},
        "http_useragent": {"provides": ["OS", "Browser", "Device type", "App identification"], "passive": True, "layer": "L7"},
        "netbios": {"provides": ["NetBIOS name", "Workgroup", "OS hints"], "passive": True, "layer": "L3"},
        "icmpv6": {"provides": ["IPv6 RA info", "Router identification"], "passive": True, "layer": "L3"},
        "lldp": {"provides": ["Switch/router model", "Port", "System name", "Capabilities"], "passive": True, "layer": "L2"},
        "cdp": {"provides": ["Cisco device ID", "Platform", "Software version", "VLAN"], "passive": True, "layer": "L2"},
        "snmp": {"provides": ["Community string", "Device version", "Management info"], "passive": True, "layer": "L3"},
        "banner": {"provides": ["Service version", "Protocol identification"], "passive": False, "layer": "L7"},
        "ip_observed": {"provides": ["IP-MAC mapping", "TTL-based OS hint"], "passive": True, "layer": "L3"},
    }

    # Build coverage report
    observed = []
    missing = []
    for source, info in ALL_SOURCES.items():
        entry = {
            "source": source,
            "provides": info["provides"],
            "passive": info["passive"],
            "layer": info["layer"],
        }
        if source in observed_sources:
            entry["status"] = "observed"
            entry["count"] = observed_sources[source]["count"]
            entry["last_seen"] = observed_sources[source]["last_seen"]
            observed.append(entry)
        else:
            entry["status"] = "not_observed"
            entry["count"] = 0
            missing.append(entry)

    # Generate recommendations
    recommendations = []
    missing_names = {m["source"] for m in missing}

    if "mdns" in missing_names:
        recommendations.append({
            "priority": "high",
            "message": "No mDNS data observed. mDNS reveals device model, friendly name, and services.",
            "action": "Ensure capture interface is on the same VLAN as this device, or enable mDNS reflection on your gateway. Alternatively, enable active probing to send mDNS queries.",
        })
    if "ssdp" in missing_names:
        recommendations.append({
            "priority": "high",
            "message": "No SSDP/UPnP data observed. SSDP reveals manufacturer, model, and firmware.",
            "action": "SSDP is multicast — capture must be on the same subnet. Enable SSDP probing for cross-VLAN discovery.",
        })
    if "dhcpv4" in missing_names and "dhcpv6" in missing_names:
        recommendations.append({
            "priority": "medium",
            "message": "No DHCP data observed. DHCP reveals hostname, vendor class, and OS fingerprint.",
            "action": "DHCP broadcasts are VLAN-local. Wait for the device to renew its lease, or capture on the device's VLAN.",
        })
    if "tcp_syn" in missing_names:
        recommendations.append({
            "priority": "medium",
            "message": "No TCP SYN observed. TCP fingerprinting reveals OS family via TTL and window size.",
            "action": "This device may not initiate TCP connections through the capture point. Consider capturing closer to the device.",
        })
    if "tls" in missing_names and "http_useragent" in missing_names:
        recommendations.append({
            "priority": "low",
            "message": "No HTTP/TLS traffic observed. These reveal OS, browser, and cloud services.",
            "action": "This device may not use web services, or traffic is routed through a different path.",
        })
    if "lldp" in missing_names and device.get("device_type") in ("switch", "router", "access_point"):
        recommendations.append({
            "priority": "high",
            "message": "No LLDP data observed for a network device. LLDP reveals exact model and firmware.",
            "action": "Ensure LLDP is enabled on this device. Capture must be on a directly connected port.",
        })

    # Evidence quality score
    raw_ev = device.get("raw_evidence", {})
    evidence_count = len(raw_ev.get("chain", [])) if isinstance(raw_ev, dict) else 0
    source_count = len(observed)
    quality = "excellent" if source_count >= 5 else "good" if source_count >= 3 else "limited" if source_count >= 2 else "minimal"

    return {
        "mac": mac,
        "confidence": device.get("confidence", 0),
        "evidence_count": evidence_count,
        "source_count": source_count,
        "quality": quality,
        "observed": observed,
        "missing": missing,
        "recommendations": recommendations,
    }


@router.get("/api/devices/{mac}/observations")
async def get_device_observations(mac: str, limit: int = 50, offset: int = 0):
    """Paginated observation history."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    try:
        sightings = await app_instance.store.sightings.for_host(mac, limit=limit)
        # Get total count
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT COUNT(*) FROM sightings WHERE hw_addr = ?", (mac,)
        )
        row = await cursor.fetchone()
        total = row[0] if row else 0
    except Exception:
        sightings = []
        total = 0

    observations = [
        {
            "source_type": s.source,
            "timestamp": s.timestamp.isoformat() if hasattr(s.timestamp, 'isoformat') else str(s.timestamp),
            "raw_data": s.payload,
            "certainty": s.certainty,
        }
        for s in sightings
    ]

    return {
        "observations": observations,
        "total": total,
        "has_more": (offset + limit) < total,
    }


@router.get("/api/devices/{mac}/activity")
async def get_device_activity(mac: str):
    """24-hour packet activity (hourly buckets)."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    try:
        conn = app_instance.store.connection
        cursor = await conn.execute(
            "SELECT strftime('%H', timestamp) as hour, COUNT(*) as cnt "
            "FROM sightings WHERE hw_addr = ? AND timestamp > datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour",
            (mac,))
        rows = await cursor.fetchall()
        # Build 24-element array indexed by hour (0-23)
        counts = [0] * 24
        for row in rows:
            try:
                h = int(row[0])
                if 0 <= h < 24:
                    counts[h] = row[1]
            except (ValueError, IndexError):
                pass
    except Exception:
        counts = [0] * 24
    return {"hourly_counts": counts}


@router.get("/api/devices/{mac}/timeline")
async def get_device_timeline(mac: str, limit: int = 100):
    """Chronological event timeline for a device."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})

    from leetha.timeline import build_timeline

    verdict = await app_instance.store.verdicts.find_by_addr(mac)
    host = await app_instance.store.hosts.find_by_addr(mac)
    override = await app_instance.store.overrides.find_by_addr(mac) if (verdict or host) else None
    device_dict = _build_device_dict(verdict, host, override) if (verdict or host) else None

    # Get sightings as observations
    try:
        sightings = await app_instance.store.sightings.for_host(mac, limit=200)
    except Exception:
        sightings = []
    observations = [{"timestamp": s.timestamp.isoformat() if hasattr(s.timestamp, 'isoformat') else str(s.timestamp),
                      "source_type": s.source, "raw_data": json.dumps(s.payload) if isinstance(s.payload, dict) else str(s.payload),
                      "confidence": int(s.certainty * 100) if s.certainty <= 1 else int(s.certainty)} for s in sightings]

    # Derive fingerprint history from verdict evidence chain
    fp_history = []
    if verdict and verdict.evidence_chain:
        for ev in verdict.evidence_chain:
            fp_history.append({
                "timestamp": ev.observed_at.isoformat() if hasattr(ev.observed_at, 'isoformat') else str(ev.observed_at),
                "device_type": ev.category,
                "manufacturer": ev.vendor,
                "os_family": ev.platform,
                "hostname": ev.hostname,
                "oui_vendor": ev.vendor if ev.source == "oui" else None,
            })

    # Derive ARP history from sightings
    arp_history = await _get_arp_history_from_sightings(mac=mac)

    # Get findings for this device as alert-compatible dicts
    findings = []
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT rule, severity, message, timestamp FROM findings WHERE hw_addr = ? ORDER BY timestamp DESC LIMIT 50",
            (mac,),
        )
        for row in await cursor.fetchall():
            findings.append({"alert_type": row[0], "severity": row[1], "message": row[2], "timestamp": row[3]})
    except Exception:
        pass

    events = build_timeline(
        mac=mac, device=device_dict, observations=observations,
        fingerprint_history=fp_history, arp_history=arp_history,
        findings=findings, limit=limit,
    )

    return {"events": events, "total": len(events)}


@router.get("/api/devices/{mac}/services")
async def get_device_services(mac: str):
    """Return discovered services for a device from sightings."""
    _validate_mac, _sanitize_hostname, _build_device_dict = _get_helpers()
    app_instance = _get_app()

    mac = _validate_mac(mac)
    if not mac:
        return JSONResponse(status_code=400, content={"error": "Invalid MAC address format"})
    services = []
    try:
        cursor = await app_instance.store.connection.execute(
            "SELECT source, payload, timestamp FROM sightings "
            "WHERE hw_addr = ? AND source IN ('service_banner', 'tls', 'mdns', 'ssdp', 'http_useragent') "
            "ORDER BY timestamp DESC LIMIT 100",
            (mac,),
        )
        rows = await cursor.fetchall()
        seen = set()
        for r in rows:
            payload = json.loads(r[1]) if isinstance(r[1], str) else (r[1] or {})
            key = (r[0], payload.get("service") or payload.get("service_type") or payload.get("sni") or "")
            if key in seen:
                continue
            seen.add(key)
            services.append({
                "protocol": r[0],
                "service": payload.get("service") or payload.get("service_type") or r[0],
                "port": payload.get("port") or payload.get("dst_port"),
                "banner": payload.get("raw_banner") or payload.get("server"),
                "sni": payload.get("sni"),
                "timestamp": r[2],
                "details": payload,
            })
    except Exception:
        pass
    # Also include old probe results if available
    try:
        old_services = await app_instance.db.get_device_services(mac)
        if isinstance(old_services, dict) and old_services.get("services"):
            services.extend(old_services["services"])
        elif isinstance(old_services, list):
            services.extend(old_services)
    except Exception:
        pass
    return {"services": services}
