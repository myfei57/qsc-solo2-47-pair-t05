"""Append-only event record stream, replayed on restart.

Every record carries a hash link to its predecessor, so the stream proves its
own integrity: editing, dropping or inserting a row invalidates the next
record's hash. Full blocks of records are additionally sealed with a signed
Merkle root, which makes any contiguous fragment independently verifiable.
"""

import json
import os
from pathlib import Path
from typing import Any

from ..clock import IdSequence, parse_id
from . import chaining
from .block import BlockSealer
from .record import AuditRecord


class ChainIntegrityError(ValueError):
    """Raised when the persisted stream fails its own hash-chain check."""


class AuditLog:
    """Keeps every control event in the order it happened."""

    LOG_NAME = "audit.log"

    def __init__(
        self,
        directory: str | None = None,
        sealer: BlockSealer | None = None,
    ) -> None:
        self._records: list[AuditRecord] = []
        self._ids = IdSequence("evt")
        self._seq = 0
        self._path = os.path.join(directory, self.LOG_NAME) if directory else None
        self._sealer = sealer
        if directory is not None:
            os.makedirs(directory, exist_ok=True)
            self._load()

    def append(
        self,
        topic: str,
        payload: Any,
        tick: int,
        generation: int = 0,
        batch_id: str = "",
    ) -> AuditRecord:
        self._seq += 1
        prev_hash = self._records[-1].hash if self._records else chaining.GENESIS_HASH
        record = AuditRecord(
            seq=self._seq,
            record_id=self._ids.next(),
            topic=topic,
            tick=int(tick),
            generation=int(generation),
            batch_id=batch_id,
            payload=payload,
            prev_hash=prev_hash,
        )
        record = AuditRecord(
            seq=record.seq,
            record_id=record.record_id,
            topic=record.topic,
            tick=record.tick,
            generation=record.generation,
            batch_id=record.batch_id,
            payload=record.payload,
            prev_hash=prev_hash,
            hash=chaining.record_hash(prev_hash, record.to_row()),
        )
        self._records.append(record)
        self._write(record)
        if self._sealer is not None:
            self._sealer.seal_new_blocks(self.record_hashes())
        return record

    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def count(self, topic: str) -> int:
        return sum(1 for record in self._records if record.topic == topic)

    @property
    def sequence(self) -> int:
        return self._seq

    @property
    def sealer(self) -> BlockSealer | None:
        return self._sealer

    def record_hashes(self) -> list[str]:
        return [record.hash for record in self._records]

    def verify_chain(self) -> bool:
        """Recompute every link. Returns False on the first broken record."""
        previous = chaining.GENESIS_HASH
        for record in self._records:
            if not record.hash:
                return False
            if record.prev_hash != previous:
                return False
            if chaining.record_hash(previous, record.to_row()) != record.hash:
                return False
            previous = record.hash
        return True

    def clear(self) -> int:
        """Empty the stream while keeping the sequence running."""
        cleared = len(self._records)
        self._records = []
        if self._path is not None:
            Path(self._path).write_text("", encoding="utf-8")
        if self._sealer is not None:
            self._sealer.reset()
        return cleared

    def _write(self, record: AuditRecord) -> None:
        if self._path is None:
            return
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_row(), sort_keys=True, ensure_ascii=True))
            handle.write("\n")

    def _load(self) -> None:
        if self._path is None or not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = AuditRecord.from_row(json.loads(line))
                self._records.append(record)
                self._seq = max(self._seq, record.seq)
                issued = parse_id(record.record_id)
                if issued is not None:
                    self._ids.restore(issued)
        self._verify_loaded_chain()
        if self._sealer is not None:
            # Only once the on-disk chain has proven intact may it be sealed:
            # sealing must never sign a tampered view of the stream.
            self._sealer.seal_new_blocks(self.record_hashes())

    def _verify_loaded_chain(self) -> None:
        # Legacy rows written before hashing existed have empty hashes and are
        # treated as an unverifiable prefix, not as tampering; the first
        # chained row is accepted as a new chain start. Any later break means
        # the file was edited outside the append path.
        start = next(
            (index for index, record in enumerate(self._records) if record.hash),
            None,
        )
        if start is None:
            return
        expected_prev = self._records[start].prev_hash
        for record in self._records[start:]:
            if not record.hash or record.prev_hash != expected_prev:
                raise ChainIntegrityError(
                    f"{self.LOG_NAME}: record {record.seq} breaks the hash chain; "
                    "the stream was edited outside the append path"
                )
            if chaining.record_hash(expected_prev, record.to_row()) != record.hash:
                raise ChainIntegrityError(
                    f"{self.LOG_NAME}: record {record.seq} hash does not match; "
                    "the stream was edited outside the append path"
                )
            expected_prev = record.hash
