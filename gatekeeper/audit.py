"""A lightweight lakehouse for the agent action audit trail.

Design intent: every policy decision - allowed or denied - is a compliance
record, and compliance records need to be queryable at scale later, not just
grep-able in a log file. Real lakehouses (Iceberg, Delta Lake, Hudi) exist to
solve that at scale: columnar files (Parquet), partitioned by a natural key
(here, the date), with a catalog layer on top so you can query "the table"
without caring how many files back it. This module implements that pattern
at a small, dependency-light scale: Parquet files partitioned by date on
disk, queried through DuckDB, which speaks SQL over the partitioned files
directly. Swapping this for a real Iceberg table later is a storage-layer
change, not a rethink of the audit model - the write path (one immutable
file per batch of decisions) and the read path (SQL over the partition) are
already shaped the way Iceberg expects.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq


@dataclass
class AuditRecord:
    audit_id: str
    timestamp: str
    agent_subject: str
    client_id: str
    action_type: str
    resource_id: str
    resource_tier: str
    allow: bool
    reason: str
    date: str  # partition key, YYYY-MM-DD, redundant with timestamp on purpose


class LakehouseAuditLog:
    """Appends decision records as Parquet, partitioned by day; queries via DuckDB."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        agent_subject: str,
        client_id: str,
        action_type: str,
        resource_id: str,
        resource_tier: str,
        allow: bool,
        reason: str,
        timestamp: Optional[datetime] = None,
    ) -> AuditRecord:
        ts = timestamp or datetime.now(timezone.utc)
        date_key = ts.strftime("%Y-%m-%d")

        entry = AuditRecord(
            audit_id=str(uuid.uuid4()),
            timestamp=ts.isoformat(),
            agent_subject=agent_subject,
            client_id=client_id,
            action_type=action_type,
            resource_id=resource_id,
            resource_tier=resource_tier,
            allow=allow,
            reason=reason,
            date=date_key,
        )
        self._write(entry, date_key)
        return entry

    def _write(self, entry: AuditRecord, date_key: str) -> None:
        partition_dir = self.root / f"date={date_key}"
        partition_dir.mkdir(parents=True, exist_ok=True)

        table = pa.Table.from_pylist([asdict(entry)])
        # One file per write, like a lakehouse commit - small-file-per-batch
        # is the realistic pattern; a real system would compact these
        # periodically, which is exactly the kind of maintenance job a real
        # Iceberg table gives you (compaction, snapshot expiry) for free.
        out_path = partition_dir / f"part-{entry.audit_id}.parquet"
        pq.write_table(table, out_path)

    def _glob(self) -> str:
        return str(self.root / "date=*" / "*.parquet")

    def query(self, sql: str) -> list[dict[str, Any]]:
        """Run arbitrary SQL against the audit trail, exposed as table `audit`."""
        con = duckdb.connect(database=":memory:")
        try:
            existing = list(self.root.glob("date=*/*.parquet"))
            if not existing:
                return []
            con.execute(
                f"CREATE VIEW audit AS SELECT * FROM read_parquet('{self._glob()}', hive_partitioning=1)"
            )
            return con.execute(sql).fetchdf().to_dict(orient="records")
        finally:
            con.close()

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.query(f"SELECT * FROM audit ORDER BY timestamp DESC LIMIT {limit}")

    def recent_denials(self, limit: int = 20) -> list[dict[str, Any]]:
        return self.query(
            f"SELECT * FROM audit WHERE allow = false ORDER BY timestamp DESC LIMIT {limit}"
        )

    def counts_by_agent(self) -> list[dict[str, Any]]:
        return self.query(
            "SELECT agent_subject, allow, count(*) AS n FROM audit "
            "GROUP BY agent_subject, allow ORDER BY agent_subject, allow"
        )
