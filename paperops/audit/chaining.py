"""Tamper-evident hashing for audit records.

Each record carries a link to its predecessor:

    body  = canonical JSON of every field except the hashes themselves
    hash  = SHA-256(prev_hash_hex + "\n" + canonical_body)

Changing, deleting or inserting a record in the middle breaks the link of the
next record, so a reader can prove the chain has not been touched without
trusting whoever holds the file.
"""

import hashlib
import json
from typing import Any, Mapping, Sequence

GENESIS_HASH = ""
HASH_ALGORITHM = "sha256"


def canonical_body(row: Mapping[str, Any]) -> bytes:
    """Deterministic byte representation of the record content."""
    fields = dict(row)
    fields.pop("prev_hash", None)
    fields.pop("hash", None)
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def record_hash(prev_hash: str, row: Mapping[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("ascii"))
    digest.update(b"\n")
    digest.update(canonical_body(row))
    return digest.hexdigest()


def chain_hashes(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    """Compute the hash every row *should* carry, in stream order."""
    previous = GENESIS_HASH
    hashes: list[str] = []
    for row in rows:
        previous = record_hash(previous, row)
        hashes.append(previous)
    return hashes
