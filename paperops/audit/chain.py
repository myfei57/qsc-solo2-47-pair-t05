"""Hash chain and Merkle proofs that let the record stream vouch for itself.

Every record is sealed with ``chain_hash = H(prev_hash, content)`` so editing,
reordering or dropping a stored record breaks every link after it.  The chain
hashes also serve as the leaves of a Merkle tree whose root can be pinned down
through a separate channel; a contiguous run of records can then be exported
with O(log n) frontier hashes and verified against that pinned root without
handing over the whole stream.
"""

import hashlib
from dataclasses import replace
from typing import Any, Mapping, Sequence

from ..store.snapshot import canonical

GENESIS_HASH = "0" * 64
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()
RECORD_DOMAIN = "paperops.audit.record/v1"
SEGMENT_FORMAT = "paperops.audit.segment/v1"

_HASH_FIELDS = ("prev_hash", "chain_hash")


def seal(prev_hash: str, content: Mapping[str, Any]) -> str:
    """Chain hash of one record: binds the content to everything before it."""
    body = canonical({"prev_hash": prev_hash, "record": content})
    return hashlib.sha256(f"{RECORD_DOMAIN}\n{body}".encode("utf-8")).hexdigest()


def seal_record(record: Any, prev_hash: str) -> Any:
    """Return a copy of the record carrying its chain link."""
    return replace(
        record,
        prev_hash=prev_hash,
        chain_hash=seal(prev_hash, record.content_row()),
    )


def content_of(row: Mapping[str, Any]) -> dict[str, Any]:
    """The fields a chain hash commits to, stripped of the chain itself."""
    return {key: value for key, value in row.items() if key not in _HASH_FIELDS}


def check_rows(rows: Sequence[Mapping[str, Any]], first_seq: int) -> list[str]:
    """Problems found in a run of rows that should be contiguous from first_seq.

    The first row's own ``prev_hash`` cannot be link-checked here (its
    predecessor lives outside the run); the Merkle leaf anchors it instead.
    """
    problems: list[str] = []
    expected_prev: str | None = None
    for index, row in enumerate(rows):
        seq = int(row["seq"])
        if seq != first_seq + index:
            problems.append(f"row at position {index} carries seq {seq}")
        prev_hash = str(row.get("prev_hash", ""))
        chain_hash = str(row.get("chain_hash", ""))
        if expected_prev is not None and prev_hash != expected_prev:
            problems.append(f"seq {seq} does not follow the previous row")
        if chain_hash != seal(prev_hash, content_of(row)):
            problems.append(f"seq {seq} content does not match its chain hash")
        expected_prev = chain_hash
    return problems


def merkle_root(leaves: Sequence[str]) -> str:
    """Root committing to the ordered leaf hashes (record chain hashes)."""
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    cut = _split(len(leaves))
    return _node(merkle_root(leaves[:cut]), merkle_root(leaves[cut:]))


def prove(leaves: Sequence[str], low: int, high: int) -> list[str]:
    """Frontier hashes letting a verifier rebuild the root from leaves low..high."""
    proof: list[str] = []
    _prove_into(leaves, low, high, 0, proof)
    return proof


def rebuild_root(
    segment_leaves: Sequence[str],
    low: int,
    high: int,
    tree_size: int,
    proof: Sequence[str],
) -> str:
    """Root recomputed from the segment leaves and the frontier hashes."""
    cursor = iter(proof)
    root = _rebuild(segment_leaves, low, high, 0, tree_size, cursor)
    if next(cursor, None) is not None:
        raise ValueError("proof carries more hashes than the tree consumes")
    return root


def _split(count: int) -> int:
    """Largest power of two strictly below count."""
    power = 1
    while power < count:
        power <<= 1
    return power >> 1


def _node(left: str, right: str) -> str:
    payload = b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(payload).hexdigest()


def _prove_into(
    leaves: Sequence[str],
    low: int,
    high: int,
    start: int,
    proof: list[str],
) -> None:
    end = start + len(leaves) - 1
    if end < low or start > high:
        proof.append(merkle_root(leaves))
        return
    if low <= start and end <= high:
        return
    cut = _split(len(leaves))
    _prove_into(leaves[:cut], low, high, start, proof)
    _prove_into(leaves[cut:], low, high, start + cut, proof)


def _rebuild(
    segment_leaves: Sequence[str],
    low: int,
    high: int,
    start: int,
    count: int,
    cursor: Any,
) -> str:
    end = start + count - 1
    if end < low or start > high:
        hash_value = next(cursor, None)
        if hash_value is None:
            raise ValueError("proof ran out of hashes")
        return hash_value
    if low <= start and end <= high:
        return merkle_root(segment_leaves[start - low : end - low + 1])
    cut = _split(count)
    left = _rebuild(segment_leaves, low, high, start, cut, cursor)
    right = _rebuild(segment_leaves, low, high, start + cut, count - cut, cursor)
    return _node(left, right)
