"""Unique names over the last few hours, in fixed memory: two rotating Bloom filters.

The stream repeats names (the precertificate and the certificate, several logs, renewals, www + apex), and a
set of every name for days would need gigabytes. A Bloom filter answers "seen recently?" in ~14 MB per
generation; when the current one fills, the older one is dropped. A name seen again after both generations
have turned over counts as new and is judged again (the catch store keeps its first-seen time).

At ``fp`` = 0.1%, about 1 in 1,000 genuinely new names is taken for a repeat and skipped: stated in the eval.
"""

from __future__ import annotations

import hashlib
import math


class _Bloom:
    def __init__(self, capacity: int, fp: float) -> None:
        self.m = max(64, int(-capacity * math.log(fp) / (math.log(2) ** 2)))
        self.k = max(1, round(self.m / capacity * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)
        self.count = 0

    def _idx(self, key: str):
        d = hashlib.blake2b(key.encode("utf-8", "surrogatepass"), digest_size=16).digest()
        h1, h2 = int.from_bytes(d[:8], "little"), int.from_bytes(d[8:], "little") | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def __contains__(self, key: str) -> bool:
        return all(self.bits[i >> 3] & (1 << (i & 7)) for i in self._idx(key))

    def add(self, key: str) -> None:
        for i in self._idx(key):
            self.bits[i >> 3] |= 1 << (i & 7)
        self.count += 1


class RecentNames:
    def __init__(self, capacity: int = 8_000_000, fp: float = 0.001) -> None:
        self.capacity, self.fp = capacity, fp
        self.cur, self.old = _Bloom(capacity, fp), None
        self.rotations = 0

    def seen_or_add(self, name: str) -> bool:
        """True if seen recently; otherwise remember it and return False."""
        if name in self.cur or (self.old is not None and name in self.old):
            return True
        if self.cur.count >= self.capacity:
            self.old, self.cur = self.cur, _Bloom(self.capacity, self.fp)
            self.rotations += 1
        self.cur.add(name)
        return False

    @property
    def memory_mb(self) -> float:
        return round((len(self.cur.bits) + (len(self.old.bits) if self.old else 0)) / 1e6, 1)
