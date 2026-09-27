"""Self-verifying fragment export.

An export hands an outside party only the records they asked for, bundled with
the signed block headers those records live in and a Merkle path for the first
record of every block the fragment touches. The holder of the public key can
then verify the fragment with no other access to the ledger:

* every block header carries a valid Ed25519 signature;
* every anchored record is part of the signed Merkle root of its block;
* every record's hash recomputes correctly and links to the previous record,
  so nothing in the fragment was changed, inserted or dropped.

The exporter cannot forge any of this without the private signing key.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .block import (
    BlockHeader,
    BlockSealer,
    Seal,
    header_hash,
    verify_seal,
)
from .chaining import record_hash
from .merkle import merkle_path, merkle_root, merkle_root_from
from .record import AuditRecord

FORMAT = "audit-fragment/v1"


class FragmentError(ValueError):
    """Raised when a requested fragment cannot be exported."""


@dataclass(frozen=True)
class Anchor:
    """A Merkle path pinning one record to a sealed block."""

    block_index: int
    seq: int
    path: tuple[str, ...]

    def to_row(self) -> dict[str, Any]:
        return {"block_index": self.block_index, "seq": self.seq, "path": list(self.path)}

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "Anchor":
        return cls(
            block_index=int(row["block_index"]),
            seq=int(row["seq"]),
            path=tuple(str(item) for item in row["path"]),
        )


def _tail_seal(
    sealer: BlockSealer,
    hashes: Sequence[str],
    last_seq: int,
) -> Seal:
    """Sign the in-progress block truncated at ``last_seq`` without storing it."""
    index = sealer.sealed_count
    start = index * sealer.block_size
    if start >= last_seq:
        raise FragmentError("tail block is already sealed")
    leaves = [bytes.fromhex(h) for h in hashes[start:last_seq]]
    existing = sealer.seals()
    prev = header_hash(existing[-1].header) if existing else ""
    header = BlockHeader(
        index=index,
        first_seq=start + 1,
        last_seq=last_seq,
        merkle_root=merkle_root(leaves).hex(),
        prev_block=prev,
    )
    return sealer.make_seal(header, persist=False)


def export_fragment(
    records: Sequence[AuditRecord],
    sealer: BlockSealer,
    first_seq: int,
    last_seq: int,
) -> dict[str, Any]:
    """Build an exportable, self-verifying document for a sequence range."""
    if first_seq < 1 or last_seq < first_seq:
        raise FragmentError("sequence range is empty or invalid")
    if last_seq > len(records):
        raise FragmentError(f"seq {last_seq} does not exist yet")
    hashes = [record.hash for record in records]

    first_block = (first_seq - 1) // sealer.block_size
    last_block = (last_seq - 1) // sealer.block_size

    # Make sure every complete block in range is durably sealed.
    sealer.seal_new_blocks(hashes)
    seals_by_index = {seal.header.index: seal for seal in sealer.seals()}
    if last_block not in seals_by_index:
        tail = _tail_seal(sealer, hashes, last_seq)
        seals_by_index[tail.header.index] = tail
    for index in range(first_block, last_block + 1):
        if index not in seals_by_index:
            raise FragmentError(f"block {index} is not sealed")

    blocks: list[dict[str, Any]] = []
    anchors: list[dict[str, Any]] = []
    for index in range(first_block, last_block + 1):
        seal = seals_by_index[index]
        header = seal.header
        blocks.append(seal.to_row())
        # Anchor the fragment's first record and the first record of every
        # later block; chain walking covers everything in between.
        anchor_seq = max(first_seq, header.first_seq)
        if anchor_seq > min(last_seq, header.last_seq):
            continue
        anchor_position = anchor_seq - header.first_seq
        block_start = index * sealer.block_size
        block_size = header.last_seq - header.first_seq + 1
        leaves = [bytes.fromhex(h) for h in hashes[block_start : block_start + block_size]]
        path = [node.hex() for node in merkle_path(leaves, anchor_position)]
        anchors.append(Anchor(index, anchor_seq, tuple(path)).to_row())

    chosen = [record.to_row() for record in records[first_seq - 1 : last_seq]]
    return {
        "format": FORMAT,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "records": chosen,
        "blocks": blocks,
        "anchors": anchors,
    }


@dataclass(frozen=True)
class FragmentReport:
    valid: bool
    records: int
    blocks: int
    anchored: int
    contiguous: bool
    links_ok: bool
    signatures_ok: bool
    errors: tuple[str, ...]


def verify_fragment(
    document: Mapping[str, Any],
    trusted_public_key: str | None = None,
) -> FragmentReport:
    """Independently verify an exported fragment.

    ``trusted_public_key`` pins the signer out of band; when it is omitted the
    signatures are still checked for self-consistency but the signer identity
    is not confirmed.
    """
    errors: list[str] = []
    rows = list(document.get("records", []))
    blocks = list(document.get("blocks", []))
    anchor_rows = list(document.get("anchors", []))
    first_seq = int(document.get("first_seq", 0))
    last_seq = int(document.get("last_seq", 0))

    # ------------------------------------------------------------ contiguity
    expected = list(range(first_seq, last_seq + 1))
    actual = [int(row.get("seq", -1)) for row in rows]
    contiguous = actual == expected
    if not contiguous:
        errors.append("records are not exactly the contiguous declared range")

    # ------------------------------------------------------------ signatures
    signatures_ok = True
    headers: dict[int, BlockHeader] = {}
    for block in blocks:
        seal = Seal.from_row(block)
        if not verify_seal(seal):
            signatures_ok = False
            errors.append(f"block {seal.header.index} signature is invalid")
        if trusted_public_key is not None and seal.public_key != trusted_public_key:
            signatures_ok = False
            errors.append(f"block {seal.header.index} is signed by an unexpected key")
        headers[seal.header.index] = seal.header

    ordered = sorted(headers.values(), key=lambda header: header.index)
    for previous, header in zip(ordered, ordered[1:]):
        if header.prev_block != header_hash(previous):
            errors.append(f"block {header.index} is not chained to block {previous.index}")

    def covering_header(seq: int) -> BlockHeader | None:
        for header in ordered:
            if header.first_seq <= seq <= header.last_seq:
                return header
        return None

    covered = True
    for seq in actual:
        if covering_header(seq) is None:
            covered = False
            errors.append(f"seq {seq} is not covered by any signed block")

    # Every block the fragment enters needs an anchor at its first present
    # record, so the chain walk is pinned at every block edge.
    block_entry_seqs = {
        max(first_seq, header.first_seq)
        for header in ordered
        if max(first_seq, header.first_seq) <= min(last_seq, header.last_seq)
    }

    # -------------------------------------------------------------- anchors
    anchors = [Anchor.from_row(row) for row in anchor_rows]
    anchors_ok = len(anchors) > 0
    anchored = 0
    anchored_seqs: set[int] = set()
    for anchor in anchors:
        header = headers.get(anchor.block_index)
        row = next((candidate for candidate in rows if int(candidate.get("seq", -1)) == anchor.seq), None)
        if header is None or row is None:
            anchors_ok = False
            errors.append(f"anchor for seq {anchor.seq} has no block or record")
            continue
        position = anchor.seq - header.first_seq
        size = header.last_seq - header.first_seq + 1
        try:
            root = merkle_root_from(
                bytes.fromhex(str(row["hash"])),
                position,
                size,
                [bytes.fromhex(item) for item in anchor.path],
            )
        except (ValueError, IndexError) as error:
            anchors_ok = False
            errors.append(f"anchor for seq {anchor.seq} has a bad Merkle path: {error}")
            continue
        if root.hex() != header.merkle_root:
            anchors_ok = False
            errors.append(f"anchor for seq {anchor.seq} does not match its block root")
            continue
        anchored += 1
        anchored_seqs.add(anchor.seq)

    for seq in sorted(block_entry_seqs):
        if seq not in anchored_seqs:
            anchors_ok = False
            errors.append(f"missing Merkle anchor for seq {seq}")

    # ----------------------------------------------------------- hash links
    links_ok = True
    by_seq = {int(row["seq"]): row for row in rows}
    for offset, seq in enumerate(actual):
        row = by_seq.get(seq)
        if row is None:
            continue
        previous_hash = str(row.get("prev_hash", ""))
        if not str(row.get("hash", "")):
            links_ok = False
            errors.append(f"seq {seq} carries no hash")
            continue
        if record_hash(previous_hash, row) != str(row["hash"]):
            links_ok = False
            errors.append(f"seq {seq} hash does not match its content")
        if offset > 0:
            prior = by_seq.get(actual[offset - 1])
            if prior is not None and previous_hash != str(prior.get("hash", "")):
                links_ok = False
                errors.append(f"seq {seq} is not linked to seq {actual[offset - 1]}")

    valid = contiguous and signatures_ok and covered and anchors_ok and links_ok
    return FragmentReport(
        valid=valid,
        records=len(rows),
        blocks=len(headers),
        anchored=anchored,
        contiguous=contiguous,
        links_ok=links_ok,
        signatures_ok=signatures_ok,
        errors=tuple(errors),
    )
