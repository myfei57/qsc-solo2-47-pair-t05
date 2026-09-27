"""Portable segments of the record stream that verify against a pinned anchor.

An export carries only the requested run of records plus the Merkle frontier
hashes around it.  Whoever holds the pinned anchor (root hash and tree size,
obtained through a channel they trust) can confirm the segment is genuine
without seeing the rest of the stream and without trusting the exporter.
"""

from typing import Any, Mapping, Sequence

from ..errors import OutOfRangeError
from . import chain
from .record import AuditRecord


def export(
    records: Sequence[AuditRecord],
    from_seq: int,
    to_seq: int,
) -> dict[str, Any]:
    """Carve records from_seq..to_seq out of the stream with a Merkle proof."""
    if not records:
        raise OutOfRangeError("cannot export from an empty record stream")
    first_seq = records[0].seq
    last_seq = records[-1].seq
    if from_seq > to_seq or from_seq < first_seq or to_seq > last_seq:
        raise OutOfRangeError(
            f"segment {from_seq}..{to_seq} falls outside the held {first_seq}..{last_seq}"
        )
    low = from_seq - first_seq
    high = to_seq - first_seq
    leaves = [record.chain_hash for record in records]
    return {
        "format": chain.SEGMENT_FORMAT,
        "first_seq": first_seq,
        "from_seq": from_seq,
        "to_seq": to_seq,
        "tree_size": len(leaves),
        "root_hash": chain.merkle_root(leaves),
        "records": [record.to_row() for record in records[low : high + 1]],
        "proof": chain.prove(leaves, low, high),
    }


def verify(
    document: Mapping[str, Any],
    anchor: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Check a segment against itself and, when given, the pinned anchor.

    Without an anchor the result only proves the segment is internally
    consistent; pinning the anchor is what ties it to the stream it claims
    to come from.
    """
    problems = _shape_problems(document)
    if not problems:
        rows = document["records"]
        problems.extend(chain.check_rows(rows, int(document["from_seq"])))
        problems.extend(_root_problems(document, rows))
    anchored = anchor is not None
    if anchored and not problems:
        problems.extend(_anchor_problems(document, anchor))
    return {
        "valid": not problems,
        "anchored": anchored,
        "problems": problems,
        "from_seq": document.get("from_seq"),
        "to_seq": document.get("to_seq"),
        "records": len(document.get("records") or []),
        "root_hash": document.get("root_hash", ""),
    }


def _shape_problems(document: Mapping[str, Any]) -> list[str]:
    try:
        first_seq = int(document["first_seq"])
        from_seq = int(document["from_seq"])
        to_seq = int(document["to_seq"])
        tree_size = int(document["tree_size"])
        rows = list(document["records"])
        proof = [str(hash_value) for hash_value in document["proof"]]
    except (KeyError, TypeError, ValueError) as error:
        return [f"malformed segment: {error}"]
    problems: list[str] = []
    if not rows:
        problems.append("segment carries no records")
    if from_seq > to_seq:
        problems.append(f"segment range {from_seq}..{to_seq} is inverted")
    if len(rows) != to_seq - from_seq + 1:
        problems.append("record count does not span from_seq..to_seq")
    if from_seq < first_seq or to_seq >= first_seq + tree_size:
        problems.append("segment range falls outside the declared tree")
    if not proof and tree_size > len(rows):
        problems.append("segment needs frontier hashes to reach the root")
    return problems


def _root_problems(document: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> list[str]:
    leaves = [str(row.get("chain_hash", "")) for row in rows]
    low = int(document["from_seq"]) - int(document["first_seq"])
    high = int(document["to_seq"]) - int(document["first_seq"])
    try:
        rebuilt = chain.rebuild_root(
            leaves, low, high, int(document["tree_size"]), list(document["proof"])
        )
    except (ValueError, TypeError) as error:
        return [f"proof does not fit the tree: {error}"]
    if rebuilt != str(document.get("root_hash", "")):
        return ["records and proof do not rebuild the segment root"]
    return []


def _anchor_problems(document: Mapping[str, Any], anchor: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    if str(anchor.get("root_hash", "")) != str(document.get("root_hash", "")):
        problems.append("segment root is not the pinned anchor root")
    if "tree_size" in anchor and int(anchor["tree_size"]) != int(document["tree_size"]):
        problems.append("segment tree size is not the pinned anchor tree size")
    return problems
