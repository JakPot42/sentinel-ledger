"""Ed25519 in plain Python, for the demos and tests only. RFC 8032.

The scenario drivers and the tests use this to play two parts no shipped program plays:
a forger who signs a record with a key of their own, and an operator who holds the real
key and re-signs a rewritten journal. The recorder signs with a Rust library. The gate and
the verifier each carry their own verification code and do not import this file.

It is slow, and it is not written to keep a private key secret from someone who can time
it. Do not sign anything that matters with it.
"""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(a, b):
    """Add two points in extended coordinates (X, Y, Z, T)."""
    f = (a[1] - a[0]) * (b[1] - b[0]) % P
    g = (a[1] + a[0]) * (b[1] + b[0]) % P
    c = 2 * a[3] * b[3] * D % P
    d = 2 * a[2] * b[2] % P
    e, ff, gg, h = g - f, d - c, d + c, g + f
    return (e * ff % P, gg * h % P, ff * gg % P, e * h % P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _x_from_y(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    return P - x if (x & 1) != sign else x


_BY = 4 * pow(5, P - 2, P) % P
_BX = _x_from_y(_BY, 0)
BASE = (_BX, _BY, 1, _BX * _BY % P)


def _compress(point):
    inverse = pow(point[2], P - 2, P)
    x, y = point[0] * inverse % P, point[1] * inverse % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _x_from_y(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _secret(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    return _compress(_mul(_secret(seed)[0], BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _secret(seed)
    public = _compress(_mul(a, BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = _compress(_mul(r, BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % L
    return big_r + ((r + k * a) % L).to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    left, right = _mul(s, BASE), _add(r, _mul(k, a))
    return (left[0] * right[2] - right[0] * left[2]) % P == 0 and (left[1] * right[2] - right[1] * left[2]) % P == 0


def sign_record(seed: bytes, record: dict) -> dict:
    """A copy of `record` carrying a signature over the canonical form of its other fields."""
    import json
    body = {k: v for k, v in record.items() if k != "sig"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return dict(body, sig=sign(seed, text.encode("utf-8")).hex())
