"""Signed block headers that anchor the record stream.

Records are grouped into blocks of fixed size. Once a block is full it is
sealed: a small header naming the record range, the Merkle root and the
previous block hash is signed with an Ed25513 key. The signature is what lets
an outside party verify an exported fragment against a public key they hold,
without trusting whoever produced the export.
"""

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from . import crypto
from .merkle import merkle_path, merkle_root
from .chaining import GENESIS_HASH

DEFAULT_BLOCK_SIZE = 64
SEAL_NAME = "audit.seals"
KEY_NAME = "audit.key"
SIGNATURE_ALGORITHM = "ed25519"


@dataclass(frozen=True)
class BlockHeader:
    """Everything that is signed when a block is sealed."""

    index: int
    first_seq: int
    last_seq: int
    merkle_root: str  # hex
    prev_block: str  # hex hash of the previous signed header, or ""

    def to_row(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "merkle_root": self.merkle_root,
            "prev_block": self.prev_block,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "BlockHeader":
        return cls(
            index=int(row["index"]),
            first_seq=int(row["first_seq"]),
            last_seq=int(row["last_seq"]),
            merkle_root=str(row["merkle_root"]),
            prev_block=str(row.get("prev_block", "")),
        )


def header_message(header: BlockHeader) -> bytes:
    """Deterministic bytes covered by the block signature."""
    return json.dumps(header.to_row(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def header_hash(header: BlockHeader) -> str:
    import hashlib

    return hashlib.sha256(header_message(header)).hexdigest()


@dataclass(frozen=True)
class Seal:
    """A sealed block: its signed header plus the signature metadata."""

    header: BlockHeader
    public_key: str  # hex
    signature: str  # hex

    def to_row(self) -> dict[str, Any]:
        row = self.header.to_row()
        row.update(
            {
                "alg": SIGNATURE_ALGORITHM,
                "public_key": self.public_key,
                "signature": self.signature,
            }
        )
        return row

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "Seal":
        return cls(
            header=BlockHeader.from_row(row),
            public_key=str(row["public_key"]),
            signature=str(row["signature"]),
        )


def verify_seal(seal: Seal) -> bool:
    """Check the signature on a block header with its embedded public key."""
    return crypto.verify(
        bytes.fromhex(seal.public_key),
        header_message(seal.header),
        bytes.fromhex(seal.signature),
    )


class SealError(ValueError):
    """Raised when a block cannot be sealed or re-sealed."""


class BlockSealer:
    """Groups records into blocks, seals them, and stores the signed headers.

    The private signing key is created on first use and kept in a separate
    file with owner-only permissions. Only the public key ever leaves with an
    export; verifiers pin it out of band.
    """

    def __init__(
        self,
        directory: str | None = None,
        block_size: int = DEFAULT_BLOCK_SIZE,
        private_seed: bytes | None = None,
    ) -> None:
        if block_size < 1:
            raise ValueError("block_size must be positive")
        self._block_size = block_size
        self._directory = directory
        self._seals_path = os.path.join(directory, SEAL_NAME) if directory else None
        self._key_path = os.path.join(directory, KEY_NAME) if directory else None
        self._seals: list[Seal] = []
        if private_seed is not None:
            self._seed = private_seed
        elif self._key_path is not None and os.path.exists(self._key_path):
            self._seed = bytes.fromhex(
                open(self._key_path, "r", encoding="ascii").read().strip()
            )
        else:
            self._seed = None
        if directory is not None:
            os.makedirs(directory, exist_ok=True)
            self._load()

    # ------------------------------------------------------------- key state

    def _ensure_key(self) -> bytes:
        if self._seed is None:
            self._seed, _ = crypto.generate_key()
            if self._key_path is not None:
                with open(self._key_path, "w", encoding="ascii") as handle:
                    handle.write(self._seed.hex())
                os.chmod(self._key_path, 0o600)
        return self._seed

    @property
    def public_key(self) -> str:
        return crypto.public_key(self._ensure_key()).hex()

    @property
    def block_size(self) -> int:
        return self._block_size

    @property
    def sealed_count(self) -> int:
        return len(self._seals)

    def last_sealed_seq(self) -> int:
        return self._seals[-1].header.last_seq if self._seals else 0

    def seals(self) -> tuple[Seal, ...]:
        return tuple(self._seals)

    # ---------------------------------------------------------------- sealing

    def sealable_blocks(self, record_count: int) -> int:
        """How many complete blocks ``record_count`` records produce."""
        return record_count // self._block_size

    def seal_new_blocks(self, record_hashes: Sequence[str]) -> tuple[Seal, ...]:
        """Seal every complete block that is not sealed yet.

        ``record_hashes`` is the hash of every record in stream order, in hex.
        """
        complete = self.sealable_blocks(len(record_hashes))
        created: list[Seal] = []
        for index in range(len(self._seals), complete):
            start = index * self._block_size
            stop = start + self._block_size
            leaves = [bytes.fromhex(h) for h in record_hashes[start:stop]]
            prev = header_hash(self._seals[-1].header) if self._seals else GENESIS_HASH
            header = BlockHeader(
                index=index,
                first_seq=start + 1,
                last_seq=stop,
                merkle_root=merkle_root(leaves).hex(),
                prev_block=prev,
            )
            created.append(self._sign_and_store(header))
        return tuple(created)

    def seal_partial(self, record_hashes: Sequence[str]) -> Seal:
        """Seal all records as a final, possibly short block (for export)."""
        count = len(record_hashes)
        if count == 0:
            raise SealError("cannot seal an empty block")
        index = len(self._seals)
        complete = self.sealable_blocks(count)
        if index < complete:
            raise SealError("full blocks must be sealed before a partial block")
        start = index * self._block_size
        if start >= count:
            raise SealError("no unsealed records to seal")
        leaves = [bytes.fromhex(h) for h in record_hashes[start:count]]
        prev = header_hash(self._seals[-1].header) if self._seals else GENESIS_HASH
        header = BlockHeader(
            index=index,
            first_seq=start + 1,
            last_seq=count,
            merkle_root=merkle_root(leaves).hex(),
            prev_block=prev,
        )
        seal = self._sign_and_store(header)
        return seal

    def make_seal(self, header: BlockHeader, persist: bool) -> Seal:
        """Sign a header; when ``persist`` is false nothing is stored.

        Exporting an in-progress tail block signs a truncated view of it
        without consuming the block index, so the canonical full block can
        still be sealed once it fills up.
        """
        seed = self._ensure_key()
        public = crypto.public_key(seed)
        signature = crypto.sign(seed, header_message(header))
        seal = Seal(header=header, public_key=public.hex(), signature=signature.hex())
        if persist:
            self._seals.append(seal)
            self._write(seal)
        return seal

    def proof_for(self, record_hashes: Sequence[str], seq: int) -> tuple[BlockHeader, list[str]]:
        """Return the sealed header covering ``seq`` and the record's Merkle path."""
        index = (seq - 1) // self._block_size
        if index >= len(self._seals):
            raise SealError(f"block containing seq {seq} is not sealed")
        seal = self._seals[index]
        start = index * self._block_size
        leaves = [bytes.fromhex(h) for h in record_hashes[start : start + self._block_size]]
        position = (seq - 1) % self._block_size
        if position >= len(leaves):
            raise SealError(f"seq {seq} is outside its block records")
        path = [node.hex() for node in merkle_path(leaves, position)]
        return seal.header, path

    def reset(self) -> None:
        """Forget seals after the stream was cleared; the signing key survives."""
        self._seals = []
        if self._seals_path is not None and os.path.exists(self._seals_path):
            os.remove(self._seals_path)

    # -------------------------------------------------------------- internals

    def _sign_and_store(self, header: BlockHeader) -> Seal:
        return self.make_seal(header, persist=True)

    def _write(self, seal: Seal) -> None:
        if self._seals_path is None:
            return
        with open(self._seals_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(seal.to_row(), sort_keys=True, ensure_ascii=True))
            handle.write("\n")

    def _load(self) -> None:
        if self._seals_path is None or not os.path.exists(self._seals_path):
            return
        with open(self._seals_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    seal = Seal.from_row(json.loads(line))
                    if not verify_seal(seal):
                        raise SealError(
                            f"{SEAL_NAME}: block {seal.header.index} has an invalid signature"
                        )
                    if self._seals:
                        previous = self._seals[-1].header
                        if seal.header.index != previous.index + 1:
                            raise SealError(
                                f"{SEAL_NAME}: block indices are not consecutive at {seal.header.index}"
                            )
                        if seal.header.prev_block != header_hash(previous):
                            raise SealError(
                                f"{SEAL_NAME}: block {seal.header.index} is not chained to its predecessor"
                            )
                    elif seal.header.index != 0:
                        raise SealError(
                            f"{SEAL_NAME}: first sealed block must have index 0, got {seal.header.index}"
                        )
                    if self._seed is not None and seal.public_key != crypto.public_key(self._seed).hex():
                        raise SealError(
                            f"{SEAL_NAME}: block {seal.header.index} is signed by a different key"
                        )
                    self._seals.append(seal)
