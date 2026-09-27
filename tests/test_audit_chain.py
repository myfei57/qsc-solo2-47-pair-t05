"""Tamper-evident hash chain, signed seals and verifiable fragments."""

import json

from paperops.audit import (
    AuditLog,
    BlockSealer,
    ChainIntegrityError,
    export_fragment,
    verify_fragment,
)
from paperops.audit.block import SealError
import pytest
from paperops.audit.chaining import record_hash
from paperops.audit.crypto import generate_key, public_key, sign, verify
from paperops.audit.merkle import merkle_path, merkle_root, merkle_root_from

RFC_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RFC_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
RFC_SIG_EMPTY = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


# --------------------------------------------------------------------- crypto


def test_ed25519_matches_rfc8032_test_vector():
    assert public_key(RFC_SEED) == RFC_PUBLIC
    assert sign(RFC_SEED, b"") == RFC_SIG_EMPTY
    assert verify(RFC_PUBLIC, b"", RFC_SIG_EMPTY)


def test_ed25519_sign_and_verify_roundtrip():
    seed, pub = generate_key()
    message = json.dumps({"v": 1, "zh": "台账"}).encode("utf-8")
    signature = sign(seed, message)
    assert verify(pub, message, signature)
    assert not verify(pub, message + b"x", signature)
    flipped = bytearray(signature)
    flipped[-1] ^= 1
    assert not verify(pub, message, bytes(flipped))


# --------------------------------------------------------------------- merkle


def test_merkle_paths_recompute_root_for_every_position():
    for size in range(1, 20):
        leaves = [bytes((i,)) * 32 for i in range(size)]
        root = merkle_root(leaves)
        for index in range(size):
            path = merkle_path(leaves, index)
            assert merkle_root_from(leaves[index], index, size, path) == root


def test_merkle_root_is_stable_as_leaves_land():
    leaves = [bytes((i,)) * 32 for i in range(5)]
    root_of_three = merkle_root(leaves[:3])
    # The first three leaves hash identically inside the bigger tree.
    assert merkle_root(leaves[:3]) == root_of_three


# ----------------------------------------------------------------------- chain


def _populate(log, count):
    for i in range(1, count + 1):
        log.append("test.event", {"n": i}, tick=i)


def test_records_carry_a_valid_hash_chain(tmp_path):
    log = AuditLog(str(tmp_path / "audit"))
    _populate(log, 10)
    assert log.verify_chain()
    records = log.records()
    assert records[0].prev_hash == ""
    for earlier, later in zip(records, records[1:]):
        assert later.prev_hash == earlier.hash
        assert later.hash == record_hash(earlier.hash, later.to_row())


def test_changing_a_persisted_record_breaks_the_chain(tmp_path):
    directory = str(tmp_path / "audit")
    log = AuditLog(directory)
    _populate(log, 6)
    path = tmp_path / "audit" / "audit.log"
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[2])
    row["payload"]["n"] = 999
    lines[2] = json.dumps(row, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ChainIntegrityError):
        AuditLog(directory)


def test_deleting_a_persisted_record_breaks_the_chain(tmp_path):
    directory = str(tmp_path / "audit")
    log = AuditLog(directory)
    _populate(log, 6)
    path = tmp_path / "audit" / "audit.log"
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ChainIntegrityError):
        AuditLog(directory)


# ---------------------------------------------------------------------- seals


def test_full_blocks_are_sealed_and_survive_restart(tmp_path):
    directory = str(tmp_path / "audit")
    sealer = BlockSealer(directory, block_size=4)
    log = AuditLog(directory, sealer)
    _populate(log, 10)

    assert sealer.sealed_count == 2
    assert sealer.last_sealed_seq() == 8

    reloaded = BlockSealer(directory, block_size=4)
    assert reloaded.sealed_count == 2
    # Key file is reused, so the public identity is stable.
    assert reloaded.public_key == sealer.public_key


def test_tampering_with_a_seal_file_is_rejected_on_load(tmp_path):
    directory = str(tmp_path / "audit")
    sealer = BlockSealer(directory, block_size=4)
    log = AuditLog(directory, sealer)
    _populate(log, 8)

    seals_path = tmp_path / "audit" / "audit.seals"
    lines = seals_path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    signature = bytearray.fromhex(row["signature"])
    signature[10] ^= 0x01
    row["signature"] = signature.hex()
    lines[0] = json.dumps(row, sort_keys=True)
    seals_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(SealError):
        BlockSealer(directory, block_size=4)


# ------------------------------------------------------------------- fragments


def _sealed_log(tmp_path, count=20, block_size=8):
    sealer = BlockSealer(str(tmp_path / "audit"), block_size=block_size)
    log = AuditLog(str(tmp_path / "audit"), sealer)
    _populate(log, count)
    return log, sealer


def test_middle_fragment_verifies_without_the_rest_of_the_log(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    report = verify_fragment(document, sealer.public_key)
    assert report.valid
    assert report.records == 8
    assert report.blocks == 2
    assert report.anchored == 2
    # Only the requested records left the building.
    assert [row["seq"] for row in document["records"]] == list(range(6, 14))


def test_single_block_and_boundary_fragments_verify(tmp_path):
    log, sealer = _sealed_log(tmp_path, count=12, block_size=4)
    for first, last in [(1, 1), (4, 4), (5, 5), (4, 5), (3, 6)]:
        document = export_fragment(log.records(), sealer, first, last)
        assert verify_fragment(document, sealer.public_key).valid


def test_fragment_reaching_the_unsealed_tail_gets_an_ephemeral_seal(tmp_path):
    log, sealer = _sealed_log(tmp_path, count=10, block_size=8)
    document = export_fragment(log.records(), sealer, 9, 10)
    report = verify_fragment(document, sealer.public_key)
    assert report.valid
    assert report.anchored == 1
    # The ephemeral partial seal must not consume the block index.
    assert sealer.sealed_count == 1


def test_fragment_rejects_tampered_payload(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    document["records"][2]["payload"]["n"] = 999
    report = verify_fragment(document, sealer.public_key)
    assert not report.valid
    assert not report.links_ok


def test_fragment_rejects_dropped_record(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    del document["records"][3]
    report = verify_fragment(document, sealer.public_key)
    assert not report.valid
    assert not report.contiguous


def test_fragment_rejects_forged_signature(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    signature = bytearray.fromhex(document["blocks"][0]["signature"])
    signature[5] ^= 0xFF
    document["blocks"][0]["signature"] = signature.hex()
    report = verify_fragment(document, sealer.public_key)
    assert not report.valid
    assert not report.signatures_ok


def test_fragment_rejects_untrusted_signing_key(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    _, other_public = generate_key()
    report = verify_fragment(document, other_public.hex())
    assert not report.valid
    assert not report.signatures_ok


def test_fragment_rejects_claim_to_records_not_exported(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    document["last_seq"] = 14
    assert not verify_fragment(document, sealer.public_key).valid


def test_fragment_rejects_inserted_record(tmp_path):
    log, sealer = _sealed_log(tmp_path)
    document = export_fragment(log.records(), sealer, 6, 13)
    forged = dict(document["records"][0])
    forged["seq"] = 6
    forged["payload"] = {"n": "injected"}
    forged["hash"] = "ab" * 32
    forged["prev_hash"] = ""
    document["records"].insert(0, forged)
    document["first_seq"] = 6
    assert not verify_fragment(document, sealer.public_key).valid


# --------------------------------------------------------------- console / api


def test_audit_sealing_export_and_verify_over_http(console, services):
    from support import call, ok

    ok(console, "POST", "/api/steam/drain", {})
    ok(console, "POST", "/api/steam/valve", {"open": True})

    sealing = json.loads(call(console, "GET", "/api/audit/sealing").to_bytes())
    assert sealing["enabled"]
    assert sealing["chain_ok"]
    assert len(sealing["public_key"]) == 64

    exported = json.loads(
        call(console, "GET", "/api/audit/export?first=1&last=2").to_bytes()
    )
    assert exported["format"] == "audit-fragment/v1"
    assert len(exported["records"]) == 2

    verified = json.loads(
        call(
            console,
            "POST",
            "/api/audit/verify",
            {"fragment": exported},
        ).to_bytes()
    )
    assert verified["valid"]
    assert verified["signatures_ok"] and verified["links_ok"]

    exported["records"][0]["payload"] = {"forged": True}
    rejected = json.loads(
        call(
            console,
            "POST",
            "/api/audit/verify",
            {"fragment": exported},
        ).to_bytes()
    )
    assert not rejected["valid"]
    assert not rejected["links_ok"]


def test_audit_clear_resets_seals_but_keeps_key(console, services):
    from support import call, ok

    ok(console, "POST", "/api/steam/drain", {})
    before = json.loads(call(console, "GET", "/api/audit/sealing").to_bytes())
    call(console, "POST", "/api/audit/clear", {})
    after = json.loads(call(console, "GET", "/api/audit/sealing").to_bytes())
    assert after["sealed_blocks"] == 0
    assert after["public_key"] == before["public_key"]
