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
                resolved INTEGER DEFAULT 0
            )
        """)
        await self._conn.commit()

    async def add(self, finding: Finding) -> int:
        cursor = await self._conn.execute("""
            INSERT INTO findings (hw_addr, rule, severity, message, timestamp, resolved)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (finding.hw_addr, finding.rule.value, finding.severity.value,
              finding.message, finding.timestamp.isoformat(), int(finding.resolved)))
        await self._conn.commit()
        return cursor.lastrowid

    async def list_active(self, limit: int = 100, offset: int = 0) -> list[Finding]:
        cursor = await self._conn.execute(
            "SELECT * FROM findings WHERE resolved = 0 "
            "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset))
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
            "SELECT COUNT(*) FROM findings WHERE resolved = 0")
        row = await cursor.fetchone()
        return row[0]

    def _row_to_finding(self, row) -> Finding:
        return Finding(
            id=row["id"],
            hw_addr=row["hw_addr"],
            rule=FindingRule(row["rule"]),
            severity=AlertSeverity(row["severity"]),
            message=row["message"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            resolved=bool(row["resolved"]),
        )
