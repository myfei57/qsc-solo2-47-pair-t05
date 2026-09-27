"""Minimal Ed25519 implementation (RFC 8032) using only the Python standard library.

The platform has no third-party crypto package available, so the signing primitive
needed to make audit block headers self-verifying is implemented here directly.
It follows RFC 8032 section 5.1 / 5.2 with extended twisted-Edwards coordinates
(RFC 8032 appendix C) for performance.

Do not "simplify" the arithmetic: the addition formulas below are the complete
addition formulas and are correct for edge cases (identical points, inverses).
"""

import hashlib
import os

# Curve parameters (RFC 8032, section 5.1)
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)

# Base point
_BY = 4 * pow(5, _P - 2, _P) % _P


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, _BX * _BY % _P)  # extended coordinates (X, Y, Z, T)


def _edwards_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Complete addition on the twisted Edwards curve, extended coordinates."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)  # neutral element in extended coordinates
    while scalar > 0:
        if scalar & 1:
            q = _edwards_add(q, point)
        point = _edwards_add(point, point)
        scalar >>= 1
    return q


def _to_affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    zi = pow(z, _P - 2, _P)
    return x * zi % _P, y * zi % _P


def _encode_point(x: int, y: int) -> bytes:
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(blob: bytes) -> tuple[int, int]:
    if len(blob) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(blob, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (blob[31] >> 7):
        x = _P - x
    if (-(x * x) + y * y - 1 - _D * x * x * y * y) % _P != 0:
        raise ValueError("point is not on the Edwards curve")
    return x, y


def _hint(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def generate_key() -> tuple[bytes, bytes]:
    """Return a fresh ``(private_seed, public_key)`` pair, both 32 bytes."""
    seed = os.urandom(32)
    return seed, public_key(seed)


def _clamped_scalar(seed: bytes) -> int:
    digest = bytearray(hashlib.sha512(seed).digest()[:32])
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    return int.from_bytes(digest, "little")


def public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("private seed must be 32 bytes")
    x, y = _to_affine(_scalar_mult(_B, _clamped_scalar(seed)))
    return _encode_point(x, y)


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("private seed must be 32 bytes")
    scalar = _clamped_scalar(seed)
    prefix = hashlib.sha512(seed).digest()[32:]
    public = public_key(seed)
    r = _hint(prefix + message) % _L
    rx, ry = _to_affine(_scalar_mult(_B, r))
    r_encoded = _encode_point(rx, ry)
    k = _hint(r_encoded + public + message) % _L
    s = (r + k * scalar) % _L
    return r_encoded + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        x, y = _decode_point(public)
        rx, ry = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _hint(signature[:32] + public + message) % _L
    s_b = _scalar_mult(_B, s)
    # R + A*k
    a_k = _scalar_mult((x, y, 1, x * y % _P), k)
    check = _edwards_add((rx, ry, 1, rx * ry % _P), a_k)
    cx, cy = _to_affine(check)
    sx, sy = _to_affine(s_b)
    return cx == sx and cy == sy
