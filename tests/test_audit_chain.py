"""Self-proving chain and portable segment verification."""

import hashlib
import json
import os

import pytest

from paperops.audit.chain import GENESIS_HASH, merkle_root, prove, rebuild_root, seal
from paperops.config import Config
from paperops.errors import ChainIntegrityError

from support import WEB_DIR, build, ok, refused, run_line


def drive_events(console):
    ok(console, "POST", "/api/steam/drain", {})
    ok(console, "POST", "/api/steam/valve", {"open": True})
    ok(console, "POST", "/api/glue/roll", {"lifted": True})


def test_records_are_sealed_into_a_chain(console, services):
    drive_events(console)
    records = services.audit.records()
    assert len(records) >= 3
    assert records[0].prev_hash == GENESIS_HASH
    for previous, record in zip(records, records[1:]):
        assert record.prev_hash == previous.chain_hash
        assert len(record.chain_hash) == 64
    anchor = services.audit.anchor()
    assert anchor["head_hash"] == records[-1].chain_hash
    assert anchor["root_hash"] == merkle_root([record.chain_hash for record in records])
    assert services.audit.verify_chain()["valid"] is True


def test_chain_replays_to_the_same_anchor(config):
    first = build(config)
    drive_events(first.console)
    second = build(config)
    assert second.audit.anchor() == first.audit.anchor()


def test_tampered_log_file_fails_to_load(config):
    services = build(config)
    drive_events(services.console)
    path = os.path.join(config.data_dir, "audit.log")
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.readlines()
    row = json.loads(lines[1])
    row["payload"] = {"forged": True}
    lines[1] = json.dumps(row, sort_keys=True) + "\n"
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)
    with pytest.raises(ChainIntegrityError):
        build(config)


def test_legacy_rows_are_sealed_on_load(config):
    os.makedirs(config.data_dir, exist_ok=True)
    path = os.path.join(config.data_dir, "audit.log")
    rows = [
        {"seq": 1, "record_id": "evt-000001", "topic": "steam.drained", "tick": 0,
         "generation": 0, "batch_id": "", "payload": None},
        {"seq": 2, "record_id": "evt-000002", "topic": "steam.valve.changed", "tick": 0,
         "generation": 0, "batch_id": "", "payload": {"open": True}},
    ]
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    services = build(config)
    records = services.audit.records()
    assert records[0].prev_hash == GENESIS_HASH
    assert records[1].prev_hash == records[0].chain_hash
    ok(services.console, "POST", "/api/glue/roll", {"lifted": True})
    assert services.audit.verify_chain()["valid"] is True


def test_clear_keeps_the_chain_running(console, services):
    drive_events(console)
    head_before = services.audit.anchor()["head_hash"]
    services.audit.clear()
    ok(console, "POST", "/api/steam/drain", {})
    records = services.audit.records()
    assert records[0].prev_hash == head_before
    assert services.audit.verify_chain()["valid"] is True


def test_exported_segment_verifies_against_the_pinned_anchor(console):
    run_line(console)
    anchor = ok(console, "GET", "/api/audit/anchor")
    segment = ok(console, "GET", "/api/audit/export?from_seq=3&to_seq=7")
    assert [row["seq"] for row in segment["records"]] == [3, 4, 5, 6, 7]
    result = ok(console, "POST", "/api/audit/verify", {"segment": segment, "anchor": anchor})
    assert result["valid"] is True
    assert result["anchored"] is True
    assert result["problems"] == []


def test_segment_verifies_against_its_own_root_without_an_anchor(console):
    run_line(console)
    segment = ok(console, "GET", "/api/audit/export?from_seq=2&to_seq=5")
    result = ok(console, "POST", "/api/audit/verify", {"segment": segment})
    assert result["valid"] is True
    assert result["anchored"] is False


def test_full_range_and_single_record_segments_verify(console):
    run_line(console)
    anchor = ok(console, "GET", "/api/audit/anchor")
    last = anchor["tree_size"]
    for query in (f"from_seq=1&to_seq={last}", "from_seq=4&to_seq=4"):
        segment = ok(console, "GET", f"/api/audit/export?{query}")
        result = ok(console, "POST", "/api/audit/verify", {"segment": segment, "anchor": anchor})
        assert result["valid"] is True, result["problems"]


def test_segment_with_altered_record_is_refused(console):
    run_line(console)
    anchor = ok(console, "GET", "/api/audit/anchor")
    segment = ok(console, "GET", "/api/audit/export?from_seq=2&to_seq=5")
    segment["records"][1]["payload"] = {"forged": True}
    result = ok(console, "POST", "/api/audit/verify", {"segment": segment, "anchor": anchor})
    assert result["valid"] is False
    assert result["problems"]


def test_segment_with_dropped_record_is_refused(console):
    run_line(console)
    anchor = ok(console, "GET", "/api/audit/anchor")
    segment = ok(console, "GET", "/api/audit/export?from_seq=2&to_seq=5")
    del segment["records"][1]
    result = ok(console, "POST", "/api/audit/verify", {"segment": segment, "anchor": anchor})
    assert result["valid"] is False


def test_segment_reforged_by_the_exporter_is_refused(console):
    """An exporter who rewrites records and re-seals them still fails the anchor."""
    run_line(console)
    anchor = ok(console, "GET", "/api/audit/anchor")
    segment = ok(console, "GET", "/api/audit/export?from_seq=2&to_seq=5")
    rows = segment["records"]
    rows[0]["payload"] = {"forged": True}
    prev = rows[0]["prev_hash"]
    for row in rows:
        content = {key: value for key, value in row.items() if "hash" not in key}
        row["prev_hash"] = prev
        row["chain_hash"] = seal(prev, content)
        prev = row["chain_hash"]
    result = ok(console, "POST", "/api/audit/verify", {"segment": segment, "anchor": anchor})
    assert result["valid"] is False


def test_segment_is_refused_once_the_anchor_moves_on(console):
    run_line(console)
    segment = ok(console, "GET", "/api/audit/export?from_seq=2&to_seq=5")
    drive_events(console)
    later_anchor = ok(console, "GET", "/api/audit/anchor")
    result = ok(console, "POST", "/api/audit/verify", {"segment": segment, "anchor": later_anchor})
    assert result["valid"] is False


def test_export_outside_the_stream_is_refused(console):
    run_line(console)
    assert refused(console, "GET", "/api/audit/export?from_seq=5&to_seq=2").status == 422
    assert refused(console, "GET", "/api/audit/export?from_seq=1&to_seq=9999").status == 422


def test_merkle_proofs_rebuild_the_root_for_every_range():
    leaves = [hashlib.sha256(f"leaf-{index}".encode()).hexdigest() for index in range(17)]
    for size in range(1, 18):
        root = merkle_root(leaves[:size])
        for low in range(size):
            for high in range(low, size):
                proof = prove(leaves[:size], low, high)
                rebuilt = rebuild_root(leaves[low : high + 1], low, high, size, proof)
                assert rebuilt == root
