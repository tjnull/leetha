"""Finding repository -- CRUD for security findings."""
from __future__ import annotations

from datetime import datetime
from leetha.store.models import Finding, FindingRule, AlertSeverity


class FindingRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hw_addr TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                resolved INTEGER DEFAULT 0,
                status TEXT DEFAULT 'new',
                disposition TEXT,
                snoozed_until TEXT,
                notes TEXT
            )
        """)
        await self._conn.commit()
        # Migrate: add columns if they don't exist
        for col, default in [("status", "'new'"), ("disposition", "NULL"),
                             ("snoozed_until", "NULL"), ("notes", "NULL")]:
            try:
                await self._conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT {default}")
                await self._conn.commit()
            except Exception:
                pass  # Column already exists

    async def add(self, finding: Finding) -> int:
        cursor = await self._conn.execute("""
            INSERT INTO findings (hw_addr, rule, severity, message, timestamp, resolved, status, disposition, snoozed_until, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding.hw_addr, finding.rule.value, finding.severity.value,
              finding.message, finding.timestamp.isoformat(), int(finding.resolved),
              finding.status, finding.disposition,
              finding.snoozed_until.isoformat() if finding.snoozed_until else None,
              finding.notes))
        await self._conn.commit()
        return cursor.lastrowid

    async def list_active(self, limit: int = 100, offset: int = 0) -> list[Finding]:
        cursor = await self._conn.execute(
            "SELECT * FROM findings WHERE resolved = 0 "
            "AND (status != 'snoozed' OR snoozed_until <= ?) "
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (datetime.now().isoformat(), limit, offset))
        rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def list_all(self, limit: int = 10000, include_resolved: bool = True) -> list[Finding]:
        if include_resolved:
            cursor = await self._conn.execute(
                "SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,))
        else:
            cursor = await self._conn.execute(
                "SELECT * FROM findings WHERE resolved = 0 ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def resolve(self, finding_id: int) -> None:
        await self._conn.execute(
            "UPDATE findings SET resolved = 1 WHERE id = ?", (finding_id,))
        await self._conn.commit()

    async def resolve_many(self, finding_ids: list[int]) -> int:
        """Resolve multiple findings in a single transaction."""
        if not finding_ids:
            return 0
        placeholders = ",".join("?" for _ in finding_ids)
        cursor = await self._conn.execute(
            f"UPDATE findings SET resolved = 1 WHERE id IN ({placeholders})",
            finding_ids,
        )
        await self._conn.commit()
        return cursor.rowcount

    async def count_active(self) -> int:
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE resolved = 0 "
            "AND (status != 'snoozed' OR snoozed_until <= ?)",
            (datetime.now().isoformat(),))
        row = await cursor.fetchone()
        return row[0]

    async def update_status(self, finding_id: int, status: str, disposition: str | None = None) -> None:
        resolved = 1 if status in ("resolved", "false_positive") else 0
        await self._conn.execute(
            "UPDATE findings SET status = ?, disposition = ?, resolved = ? WHERE id = ?",
            (status, disposition, resolved, finding_id))
        await self._conn.commit()

    async def snooze(self, finding_id: int, until: datetime) -> None:
        await self._conn.execute(
            "UPDATE findings SET status = 'snoozed', snoozed_until = ? WHERE id = ?",
            (until.isoformat(), finding_id))
        await self._conn.commit()

    async def unsnooze_expired(self) -> int:
        """Unsnooze findings whose snooze has expired."""
        now = datetime.now().isoformat()
        cursor = await self._conn.execute(
            "UPDATE findings SET status = 'new', snoozed_until = NULL "
            "WHERE status = 'snoozed' AND snoozed_until <= ?", (now,))
        await self._conn.commit()
        return cursor.rowcount

    async def update_notes(self, finding_id: int, notes: str) -> None:
        await self._conn.execute(
            "UPDATE findings SET notes = ? WHERE id = ?", (notes, finding_id))
        await self._conn.commit()

    async def list_by_status(self, status: str, limit: int = 1000) -> list[Finding]:
        cursor = await self._conn.execute(
            "SELECT * FROM findings WHERE status = ? ORDER BY timestamp DESC LIMIT ?",
            (status, limit))
        rows = await cursor.fetchall()
        return [self._row_to_finding(r) for r in rows]

    def _row_to_finding(self, row) -> Finding:
        # sqlite3.Row doesn't support .get(), use try/except for new columns
        snoozed = None
        try:
            val = row["snoozed_until"]
            if val:
                snoozed = datetime.fromisoformat(val)
        except (KeyError, IndexError, ValueError):
            pass

        try:
            status = row["status"] or "new"
        except (KeyError, IndexError):
            status = "new"

        try:
            disposition = row["disposition"]
        except (KeyError, IndexError):
            disposition = None

        try:
            notes = row["notes"]
        except (KeyError, IndexError):
            notes = None

        return Finding(
            id=row["id"],
            hw_addr=row["hw_addr"],
            rule=FindingRule(row["rule"]),
            severity=AlertSeverity(row["severity"]),
            message=row["message"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            resolved=bool(row["resolved"]),
            status=status,
            disposition=disposition,
            snoozed_until=snoozed,
            notes=notes,
        )
