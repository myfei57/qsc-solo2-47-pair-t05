"""Event capture and querying."""

from typing import Any, Mapping

from ..clock import LogicalClock
from ..event import Event, EventBus
from ..verdict import RecordFilter
from . import query, segment, summary
from .chain import check_rows, merkle_root
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

    def anchor(self) -> dict[str, Any]:
        """The values an outside party pins down to hold the stream to account."""
        records = self._log.records()
        return {
            "sequence": self._log.sequence,
            "first_seq": records[0].seq if records else 0,
            "tree_size": len(records),
            "head_hash": self._log.head_hash,
            "root_hash": merkle_root(self._log.chain_hashes()),
        }

    def verify_chain(self) -> dict[str, Any]:
        """Re-check every link of the stream currently held."""
        records = self._log.records()
        first_seq = records[0].seq if records else 1
        problems = check_rows([record.to_row() for record in records], first_seq)
        return {"valid": not problems, "problems": problems, "records": len(records)}

    def export_segment(self, from_seq: int, to_seq: int) -> dict[str, Any]:
        """A portable run of records an outside party can verify on their own."""
        return segment.export(self._log.records(), from_seq, to_seq)

    def verify_segment(
        self,
        document: Mapping[str, Any],
        anchor: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return segment.verify(document, anchor)

    def count(self, topic: str) -> int:
        return self._log.count(topic)

    def clear(self) -> int:
        return self._log.clear()

    @property
    def sequence(self) -> int:
        return self._log.sequence

    def _capture(self, event: Event) -> None:
        self._log.append(event.topic, event.payload, self._clock.tick)
