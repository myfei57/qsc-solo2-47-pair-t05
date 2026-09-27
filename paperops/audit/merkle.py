"""Merkle tree over record hashes (RFC 6962 style).

A block's Merkle root lets a verifier confirm that a single record really
belongs in the block, using only ``log2(block_size)`` sibling hashes, without
seeing the rest of the block.
"""

import hashlib
from typing import Sequence


def _h(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Root of a Merkle tree; a lone leaf is its own root.

    Following RFC 6962, when a level has an odd number of nodes the last node
    is paired with itself, which makes the tree stable as more leaves land.
    """
    if not leaves:
        raise ValueError("cannot build a Merkle tree without leaves")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_h(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaves: Sequence[bytes], index: int) -> list[bytes]:
    """Sibling hashes needed to recompute the root from ``leaves[index]``."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    level = list(leaves)
    position = index
    path: list[bytes] = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = position ^ 1
        path.append(level[sibling])
        level = [_h(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return path


def merkle_root_from(leaf: bytes, index: int, size: int, path: Sequence[bytes]) -> bytes:
    """Recompute a root given one leaf, its position, and its Merkle path."""
    if size <= 0 or not 0 <= index < size:
        raise ValueError("invalid leaf position")
    node = leaf
    position = index
    remaining = size
    step = 0
    while remaining > 1:
        if step >= len(path):
            raise ValueError("Merkle path is too short")
        sibling = path[step]
        if position & 1:
            node = _h(sibling, node)
        else:
            if position + 1 == remaining:
                # Odd last node was paired with itself on this level.
                node = _h(node, node)
            else:
                node = _h(node, sibling)
        position //= 2
        remaining = (remaining + 1) // 2
        step += 1
    return node
