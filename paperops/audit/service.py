"""Event capture and querying."""

from typing import Any, Mapping

from ..clock import LogicalClock
from ..event import Event, EventBus
from ..verdict import RecordFilter
from . import query, summary
from .block import BlockSealer
from .fragment import FragmentReport, export_fragment, verify_fragment
from .log import AuditLog
from .record import AuditRecord


class AuditService:
    """Records every published control event and answers filtered history queries."""

    def __init__(self, log: AuditLog, bus: EventBus, clock: LogicalClock) -> None:
        self._log = log
        self._bus = bus
        self._clock = clock

    def wire(self) -> None:
        """Capture every event published on the bus."""
        self._bus.subscribe("", self._capture)

    def record(
        self,
        topic: str,
        payload: Any,
        generation: int = 0,
        batch_id: str = "",
    ) -> AuditRecord:
        return self._log.append(
            topic,
            payload,
            self._clock.tick,
            generation=generation,
            batch_id=batch_id,
        )

    def records(self) -> tuple[AuditRecord, ...]:
        return self._log.records()

    def query(self, record_filter: RecordFilter, limit: int = 0) -> list[AuditRecord]:
        return query.select(self._log.records(), record_filter, limit)

    def by_topic(self, topic: str, limit: int = 0) -> list[AuditRecord]:
        return self.query(RecordFilter(topic=topic), limit)

    def news(self, limit: int = 0) -> list[AuditRecord]:
        records = query.newest_first(self._log.records())
        if limit > 0:
            records = records[:limit]
        return records

    def summary(self) -> dict[str, Any]:
        return summary.summarize(self._log.records())

    def count(self, topic: str) -> int:
        return self._log.count(topic)

    def clear(self) -> int:
        return self._log.clear()

    @property
    def sequence(self) -> int:
        return self._log.sequence

    # ---------------------------------------------------- tamper-evident chain

    @property
    def sealer(self) -> BlockSealer | None:
        return self._log.sealer

    def sealing(self) -> dict[str, Any]:
        """Current state of the sealing layer."""
        sealer = self._log.sealer
        if sealer is None:
            return {"enabled": False, "chain_ok": self.verify_chain()}
        sealer.seal_new_blocks(self._log.record_hashes())
        return {
            "enabled": True,
            "chain_ok": self.verify_chain(),
            "block_size": sealer.block_size,
            "sealed_blocks": sealer.sealed_count,
            "sealed_records": sealer.last_sealed_seq(),
            "total_records": len(self._log.records()),
            "public_key": sealer.public_key,
        }

    def verify_chain(self) -> bool:
        """Recompute the whole record hash chain from disk-loaded records."""
        return self._log.verify_chain()

    def export_fragment(self, first_seq: int, last_seq: int) -> dict[str, Any]:
        """Produce a self-verifying export covering a sequence range."""
        sealer = self._log.sealer
        if sealer is None:
            raise RuntimeError("audit log has no block sealer configured")
        return export_fragment(self._log.records(), sealer, first_seq, last_seq)

    def verify_fragment(
        self,
        document: Mapping[str, Any],
        trusted_public_key: str | None = None,
    ) -> FragmentReport:
        """Verify an export, pinning this ledger's signing key by default."""
        sealer = self._log.sealer
        if trusted_public_key is None and sealer is not None:
            trusted_public_key = sealer.public_key
        return verify_fragment(document, trusted_public_key)

    def _capture(self, event: Event) -> None:
        self._log.append(event.topic, event.payload, self._clock.tick)
