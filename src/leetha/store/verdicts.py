"""Verdict repository -- computed host assessments."""
from __future__ import annotations

import json
from datetime import datetime
from leetha.evidence.models import Evidence, Verdict


class VerdictRepository:
    def __init__(self, conn):
        self._conn = conn

    async def create_tables(self):
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS verdicts (
                hw_addr TEXT PRIMARY KEY,
                category TEXT,
                vendor TEXT,
                platform TEXT,
                platform_version TEXT,
                model TEXT,
                hostname TEXT,
                certainty INTEGER DEFAULT 0,
                evidence_chain TEXT DEFAULT '[]',
                computed_at TEXT NOT NULL
            )
        """)
        await self._conn.commit()

    async def upsert(self, verdict: Verdict) -> None:
        chain_json = json.dumps([e.to_dict() for e in verdict.evidence_chain])
        await self._conn.execute("""
            INSERT INTO verdicts (hw_addr, category, vendor, platform,
                                  platform_version, model, hostname,
                                  certainty, evidence_chain, computed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hw_addr) DO UPDATE SET
                category = excluded.category,
                vendor = excluded.vendor,
                platform = excluded.platform,
                platform_version = excluded.platform_version,
                model = excluded.model,
                hostname = COALESCE(excluded.hostname, verdicts.hostname),
                certainty = excluded.certainty,
                evidence_chain = excluded.evidence_chain,
                computed_at = excluded.computed_at
        """, (verdict.hw_addr, verdict.category, verdict.vendor,
              verdict.platform, verdict.platform_version, verdict.model,
              verdict.hostname, verdict.certainty, chain_json,
              verdict.computed_at.isoformat()))
        await self._conn.commit()

    async def find_by_addr(self, hw_addr: str) -> Verdict | None:
        cursor = await self._conn.execute(
            "SELECT * FROM verdicts WHERE hw_addr = ?", (hw_addr,))
        row = await cursor.fetchone()
        if not row:
            return None
        return self._row_to_verdict(row)

    async def find_all(self, limit: int = 500) -> list[Verdict]:
        cursor = await self._conn.execute(
            "SELECT * FROM verdicts ORDER BY certainty DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [self._row_to_verdict(r) for r in rows]

    async def list_devices(
        self,
        *,
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
    ) -> tuple[list[dict], int]:
        """Return paginated, filtered device list with total count.

        Performs a single JOIN between verdicts and hosts instead of N+1 queries.
        Returns (rows, total_count).
        """
        # Query from hosts LEFT JOIN verdicts so every discovered device
        # appears even if no verdict has been computed yet.
        # ip_sort_key: convert dotted-quad IPv4 to a 32-bit integer for
        # correct numeric sorting (e.g. .2 before .100).
        _IP_SORT_EXPR = (
            "CASE WHEN h.ip_addr IS NOT NULL AND INSTR(h.ip_addr, '.') > 0 THEN"
            "  CAST(SUBSTR(h.ip_addr, 1, INSTR(h.ip_addr, '.') - 1) AS INTEGER) * 16777216"
            " + CAST(SUBSTR(h.ip_addr, INSTR(h.ip_addr, '.') + 1,"
            "    INSTR(SUBSTR(h.ip_addr, INSTR(h.ip_addr, '.') + 1), '.') - 1) AS INTEGER) * 65536"
            " + CAST(SUBSTR(h.ip_addr,"
            "    INSTR(h.ip_addr, '.') + INSTR(SUBSTR(h.ip_addr, INSTR(h.ip_addr, '.') + 1), '.') + 1,"
            "    INSTR(SUBSTR(h.ip_addr,"
            "      INSTR(h.ip_addr, '.') + INSTR(SUBSTR(h.ip_addr, INSTR(h.ip_addr, '.') + 1), '.') + 1"
            "    ), '.') - 1) AS INTEGER) * 256"
            " + CAST(SUBSTR(h.ip_addr,"
            "    INSTR(h.ip_addr, '.') + INSTR(SUBSTR(h.ip_addr, INSTR(h.ip_addr, '.') + 1), '.')"
            "    + INSTR(SUBSTR(h.ip_addr,"
            "        INSTR(h.ip_addr, '.') + INSTR(SUBSTR(h.ip_addr, INSTR(h.ip_addr, '.') + 1), '.') + 1"
            "      ), '.') + 1"
            "  ) AS INTEGER)"
            " ELSE 4294967295 END"
        )
        select = f"""
            SELECT h.hw_addr, v.category, v.vendor, v.platform,
                   v.platform_version, v.model, v.hostname, v.certainty,
                   v.evidence_chain,
                   h.ip_addr, h.ip_v6, h.discovered_at, h.last_active,
                   h.mac_randomized, h.real_hw_addr, h.disposition,
                   h.identity_id,
                   {_IP_SORT_EXPR} AS ip_sort_key
            FROM hosts h
            LEFT JOIN verdicts v ON h.hw_addr = v.hw_addr
        """
        count_select = """
            SELECT COUNT(*)
            FROM hosts h
            LEFT JOIN verdicts v ON h.hw_addr = v.hw_addr
        """

        conditions: list[str] = []
        params: list = []

        if q:
            conditions.append(
                "(h.hw_addr LIKE ? OR v.hostname LIKE ? OR v.vendor LIKE ? OR h.ip_addr LIKE ?)"
            )
            like = f"%{q}%"
            params.extend([like, like, like, like])
        if manufacturer:
            conditions.append("v.vendor = ?")
            params.append(manufacturer)
        if device_type:
            conditions.append("v.category = ?")
            params.append(device_type)
        if os_family:
            conditions.append("v.platform = ?")
            params.append(os_family)
        if alert_status:
            conditions.append("h.disposition = ?")
            params.append(alert_status)
        if confidence_min is not None:
            conditions.append("COALESCE(v.certainty, 0) >= ?")
            params.append(confidence_min)
        if interface:
            conditions.append(
                "h.hw_addr IN (SELECT DISTINCT hw_addr FROM sightings WHERE interface = ?)"
            )
            params.append(interface)

        where = ""
        if conditions:
            where = " WHERE " + " AND ".join(conditions)

        sort_col_map = {
            "last_seen": "h.last_active",
            "first_seen": "h.discovered_at",
            "confidence": "COALESCE(v.certainty, 0)",
            "mac": "h.hw_addr",
            "manufacturer": "v.vendor",
            "device_type": "v.category",
            "hostname": "v.hostname",
            "os_family": "v.platform",
            "alert_status": "h.disposition",
            # Sort IPv4 numerically. SQLite CAST('192.168.1.2' AS INTEGER)
            # only parses the first octet, so we compute a full 32-bit
            # integer from the four octets for correct ordering.
            "ip_v4": "ip_sort_key",
        }
        sort_col = sort_col_map.get(sort, "h.discovered_at")
        sort_dir = "DESC" if order == "desc" else "ASC"

        cursor = await self._conn.execute(count_select + where, params)
        total = (await cursor.fetchone())[0]

        offset = (page - 1) * per_page
        full_query = f"{select}{where} ORDER BY {sort_col} {sort_dir} NULLS LAST LIMIT ? OFFSET ?"
        cursor = await self._conn.execute(full_query, params + [per_page, offset])
        rows = await cursor.fetchall()

        devices = []
        for row in rows:
            devices.append({
                "mac": row["hw_addr"],
                "manufacturer": row["vendor"],
                "device_type": row["category"],
                "os_family": row["platform"],
                "os_version": row["platform_version"],
                "hostname": row["hostname"],
                "confidence": row["certainty"] or 0,
                "model": row["model"],
                "ip_v4": row["ip_addr"],
                "ip_v6": row["ip_v6"],
                "first_seen": row["discovered_at"],
                "last_seen": row["last_active"],
                "alert_status": row["disposition"] or "new",
                "is_randomized_mac": bool(row["mac_randomized"]) if row["mac_randomized"] is not None else False,
                "correlated_mac": row["real_hw_addr"],
                "identity_id": row["identity_id"] if "identity_id" in row.keys() else None,
            })
            chain_raw = row["evidence_chain"]
            if chain_raw:
                chain = json.loads(chain_raw) if isinstance(chain_raw, str) else chain_raw
                devices[-1]["raw_evidence"] = {
                    "source_count": len(set(e.get("source", "") for e in chain)),
                }
            else:
                devices[-1]["raw_evidence"] = {}

        return devices, total

    def _row_to_verdict(self, row) -> Verdict:
        chain_data = json.loads(row["evidence_chain"]) if row["evidence_chain"] else []
        evidence_chain = []
        for e in chain_data:
            evidence_chain.append(Evidence(
                source=e.get("source", ""),
                method=e.get("method", ""),
                certainty=e.get("certainty", 0.0),
                category=e.get("category"),
                vendor=e.get("vendor"),
                platform=e.get("platform"),
                platform_version=e.get("platform_version"),
                model=e.get("model"),
                hostname=e.get("hostname"),
                raw=e.get("raw", {}),
            ))
        return Verdict(
            hw_addr=row["hw_addr"],
            category=row["category"],
            vendor=row["vendor"],
            platform=row["platform"],
            platform_version=row["platform_version"],
            model=row["model"],
            hostname=row["hostname"],
            certainty=row["certainty"],
            evidence_chain=evidence_chain,
            computed_at=datetime.fromisoformat(row["computed_at"]),
        )
