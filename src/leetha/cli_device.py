"""Phase A.1 — leetha device CLI: custom-property set + tag add/remove."""

from __future__ import annotations

from leetha.config import get_config
from leetha.store.database import Database


_VALID_CRITICALITY = {"low", "medium", "high", "critical"}


async def handle_device_command(parsed_args) -> int:
    """Dispatch the 'device' subcommand. Returns shell exit code."""
    cfg = get_config()
    db = Database(cfg.db_path)
    await db.initialize()
    try:
        action = getattr(parsed_args, "device_action", None)
        if action == "set":
            return await _cmd_set(db, parsed_args)
        if action == "tags":
            sub = getattr(parsed_args, "tags_action", None)
            if sub == "add":
                return await _cmd_tags_add(db, parsed_args)
            if sub == "remove":
                return await _cmd_tags_remove(db, parsed_args)
            print("Usage: leetha device tags {add|remove} <mac> <tag>")
            return 2
        if action in ("approve", "reject", "revoke"):
            return await _cmd_authorize(db, parsed_args, action)
        print("Usage: leetha device {set|tags|approve|reject|revoke} ...")
        return 2
    finally:
        await db.close()


async def handle_baseline_command(parsed_args) -> int:
    """Dispatch the 'baseline' subcommand (Phase A.2)."""
    cfg = get_config()
    db = Database(cfg.db_path)
    await db.initialize()
    try:
        action = getattr(parsed_args, "baseline_action", None)
        if action == "set":
            touched = await db.baseline_set(actor="baseline")
            print(f"Baseline set: approved {touched} previously-unapproved device(s).")
            return 0
        if action == "status":
            status = await db.baseline_status()
            print(
                f"approved={status['approved']} "
                f"unapproved={status['unapproved']} "
                f"rejected={status['rejected']}"
            )
            if status["last_baseline_at"]:
                print(f"last_baseline_at={status['last_baseline_at']}")
            return 0
        print("Usage: leetha baseline {set|status}")
        return 2
    finally:
        await db.close()


async def _cmd_authorize(db: Database, args, action: str) -> int:
    mac = args.mac
    existing = await db.get_device(mac)
    if existing is None:
        print(f"Device {mac} not found.")
        return 1
    actor = getattr(args, "actor", None) or "cli"
    reason = getattr(args, "reason", None)
    if action == "approve":
        dev = await db.approve_device(mac, actor=actor, reason=reason)
    elif action == "reject":
        dev = await db.reject_device(mac, actor=actor, reason=reason)
    else:  # revoke
        dev = await db.revoke_device(mac, actor=actor, reason=reason)
    assert dev is not None
    print(f"{mac} → {dev.authorization} (by {actor})")
    return 0


async def _cmd_set(db: Database, args) -> int:
    mac = args.mac
    existing = await db.get_device(mac)
    if existing is None:
        print(f"Device {mac} not found.")
        return 1

    updates: dict = {}
    for key in ("owner", "location", "notes"):
        val = getattr(args, key, None)
        if val is not None:
            updates[key] = val

    criticality = getattr(args, "criticality", None)
    if criticality is not None:
        if criticality not in _VALID_CRITICALITY:
            print(f"Invalid criticality: {criticality!r}. "
                  f"Choose from {sorted(_VALID_CRITICALITY)}.")
            return 2
        updates["criticality"] = criticality

    tags_raw = getattr(args, "tags", None)
    if tags_raw is not None:
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        updates["tags"] = tags

    if not updates:
        print("No fields to set. Use --owner / --location / --criticality / "
              "--tags / --notes.")
        return 2

    await db.update_device_props(mac, **updates)
    print(f"Updated {mac}: {updates}")
    return 0


async def _cmd_tags_add(db: Database, args) -> int:
    dev = await db.get_device(args.mac)
    if dev is None:
        print(f"Device {args.mac} not found.")
        return 1
    tag = args.tag.strip()
    if not tag:
        print("Tag must be non-empty.")
        return 2
    new_tags = list(dev.tags)
    if tag not in new_tags:
        new_tags.append(tag)
    await db.update_device_props(args.mac, tags=new_tags)
    print(f"Tags on {args.mac}: {new_tags}")
    return 0


async def _cmd_tags_remove(db: Database, args) -> int:
    dev = await db.get_device(args.mac)
    if dev is None:
        print(f"Device {args.mac} not found.")
        return 1
    new_tags = [t for t in dev.tags if t != args.tag]
    await db.update_device_props(args.mac, tags=new_tags)
    print(f"Tags on {args.mac}: {new_tags}")
    return 0
