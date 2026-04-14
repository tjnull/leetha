"""Identity repository -- resolved device identity storage."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from leetha.store.models import Identity


class IdentityRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                primary_mac TEXT UNIQUE NOT NULL,
                manufacturer TEXT,
                device_type TEXT,
                os_family TEXT,
                os_version TEXT,
                hostname TEXT,
                confidence INTEGER DEFAULT 0,
                fingerprint TEXT DEFAULT '{}',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_identities_mac ON identities(primary_mac)")
        await self._conn.commit()

    async def find_or_create(self, primary_mac: str) -> Identity:
        now = datetime.now(timezone.utc)
        # INSERT OR IGNORE avoids TOCTOU race: if two workers try to create
        # the same identity simultaneously, the second INSERT is a no-op
        # instead of a UNIQUE constraint violation.
        await self._conn.execute("""
            INSERT OR IGNORE INTO identities
                (primary_mac, confidence, fingerprint, first_seen, last_seen)
            VALUES (?, 0, '{}', ?, ?)
        """, (primary_mac, now.isoformat(), now.isoformat()))
        await self._conn.commit()
        return await self.find_by_mac(primary_mac)

    async def find_by_mac(self, primary_mac: str) -> Identity | None:
        cursor = await self._conn.execute(
            "SELECT * FROM identities WHERE primary_mac = ?", (primary_mac,))
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_identity(row)

    async def find_by_id(self, identity_id: int) -> Identity | None:
        cursor = await self._conn.execute(
            "SELECT * FROM identities WHERE id = ?", (identity_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_identity(row)

    async def find_all(self, limit: int = 500) -> list[Identity]:
        cursor = await self._conn.execute(
            "SELECT * FROM identities ORDER BY last_seen DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_identity(r) for r in rows]

    async def update(self, identity: Identity) -> None:
        await self._conn.execute("""
            UPDATE identities SET
                manufacturer = COALESCE(?, manufacturer),
                device_type = COALESCE(?, device_type),
                os_family = COALESCE(?, os_family),
                os_version = COALESCE(?, os_version),
                hostname = COALESCE(?, hostname),
                confidence = MAX(confidence, ?),
                fingerprint = ?,
                last_seen = ?
            WHERE primary_mac = ?
        """, (identity.manufacturer, identity.device_type,
              identity.os_family, identity.os_version,
              identity.hostname, identity.confidence,
              json.dumps(identity.fingerprint),
              identity.last_seen.isoformat(),
              identity.primary_mac))
        await self._conn.commit()

    async def get_macs_for_identity(self, identity_id: int) -> list[str]:
        cursor = await self._conn.execute(
            "SELECT hw_addr FROM hosts WHERE identity_id = ?", (identity_id,))
        rows = await cursor.fetchall()
        return [row["hw_addr"] for row in rows]

    def _row_to_identity(self, row) -> Identity:
        fp = row["fingerprint"]
        return Identity(
            id=row["id"],
            primary_mac=row["primary_mac"],
            manufacturer=row["manufacturer"],
            device_type=row["device_type"],
            os_family=row["os_family"],
            os_version=row["os_version"],
            hostname=row["hostname"],
            confidence=row["confidence"],
            fingerprint=json.loads(fp) if fp else {},
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
        )
