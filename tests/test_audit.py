from __future__ import annotations

from gatekeeper.audit import LakehouseAuditLog


def test_record_writes_a_partitioned_parquet_file(tmp_path):
    log = LakehouseAuditLog(tmp_path)
    entry = log.record(
        agent_subject="agent-1",
        client_id="demo-agent",
        action_type="read",
        resource_id="doc-1",
        resource_tier="standard",
        allow=True,
        reason="read-only action permitted for any authenticated agent",
    )

    partition_dirs = list(tmp_path.glob("date=*"))
    assert len(partition_dirs) == 1
    files = list(partition_dirs[0].glob("*.parquet"))
    assert len(files) == 1
    assert entry.date == partition_dirs[0].name.split("=")[1]


def test_query_round_trips_written_records(tmp_path):
    log = LakehouseAuditLog(tmp_path)
    log.record(
        agent_subject="agent-1", client_id="c", action_type="read",
        resource_id="r1", resource_tier="standard", allow=True, reason="ok",
    )
    log.record(
        agent_subject="agent-2", client_id="c", action_type="write",
        resource_id="r2", resource_tier="critical", allow=False, reason="blocked",
    )

    rows = log.query("SELECT * FROM audit ORDER BY agent_subject")
    assert len(rows) == 2
    assert rows[0]["agent_subject"] == "agent-1"
    assert rows[0]["allow"] is True
    assert rows[1]["agent_subject"] == "agent-2"
    assert rows[1]["allow"] is False


def test_recent_denials_only_returns_denied_records(tmp_path):
    log = LakehouseAuditLog(tmp_path)
    log.record(
        agent_subject="agent-1", client_id="c", action_type="read",
        resource_id="r1", resource_tier="standard", allow=True, reason="ok",
    )
    log.record(
        agent_subject="agent-2", client_id="c", action_type="destructive",
        resource_id="r2", resource_tier="standard", allow=False, reason="outside hours",
    )

    denials = log.recent_denials()
    assert len(denials) == 1
    assert denials[0]["agent_subject"] == "agent-2"
    assert denials[0]["reason"] == "outside hours"


def test_query_on_empty_log_returns_empty_list(tmp_path):
    log = LakehouseAuditLog(tmp_path)
    assert log.recent() == []
    assert log.recent_denials() == []


def test_counts_by_agent_aggregates_correctly(tmp_path):
    log = LakehouseAuditLog(tmp_path)
    for allow in (True, True, False):
        log.record(
            agent_subject="agent-1", client_id="c", action_type="write",
            resource_id="r", resource_tier="standard", allow=allow, reason="x",
        )

    counts = log.counts_by_agent()
    as_map = {(row["agent_subject"], row["allow"]): row["n"] for row in counts}
    assert as_map[("agent-1", True)] == 2
    assert as_map[("agent-1", False)] == 1
