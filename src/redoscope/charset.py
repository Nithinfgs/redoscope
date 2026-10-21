"""A small immutable set of Unicode code points stored as sorted ranges."""

from __future__ import annotations

from dataclasses import dataclass

MAX_CP = 0x10FFFF


def _normalize(ranges: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(r for r in ranges if r[0] <= r[1]):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return tuple(out)


@dataclass(frozen=True)
class CharSet:
    ranges: tuple[tuple[int, int], ...] = ()

    @staticmethod
    def of(*ranges: tuple[int, int]) -> CharSet:
        return CharSet(_normalize(list(ranges)))

    @staticmethod
    def char(ch: str) -> CharSet:
        cp = ord(ch)
        return CharSet(((cp, cp),))

    def is_empty(self) -> bool:
        return not self.ranges

    def union(self, other: CharSet) -> CharSet:
        return CharSet(_normalize(list(self.ranges) + list(other.ranges)))

    def intersect(self, other: CharSet) -> CharSet:
        out: list[tuple[int, int]] = []
        for a_lo, a_hi in self.ranges:
            for b_lo, b_hi in other.ranges:
                lo, hi = max(a_lo, b_lo), min(a_hi, b_hi)
                if lo <= hi:
                    out.append((lo, hi))
        return CharSet(_normalize(out))

    def negate(self) -> CharSet:
        out: list[tuple[int, int]] = []
        prev = 0
        for lo, hi in self.ranges:
            if lo > prev:
                out.append((prev, lo - 1))
            prev = hi + 1
        if prev <= MAX_CP:
            out.append((prev, MAX_CP))
        return CharSet(tuple(out))

    def contains(self, ch: str) -> bool:
        cp = ord(ch)
        return any(lo <= cp <= hi for lo, hi in self.ranges)

    def with_case_variants(self) -> CharSet:
        """Add the ASCII case counterpart of every letter (for re.IGNORECASE)."""
        extra: list[tuple[int, int]] = []
        for lo, hi in self.ranges:
            for cp in range(max(lo, 65), min(hi, 90) + 1):
                extra.append((cp + 32, cp + 32))
            for cp in range(max(lo, 97), min(hi, 122) + 1):
                extra.append((cp - 32, cp - 32))
        return self.union(CharSet(_normalize(extra))) if extra else self

    def sample(self) -> str:
        """Pick a readable representative character (letters, digits, then anything)."""
        for preferred in ("a", "A", "0", "_", " ", "-", ".", "x"):
            if self.contains(preferred):
                return preferred
        for lo, hi in self.ranges:
            for cp in range(max(lo, 33), min(hi, 126) + 1):
                return chr(cp)
        if self.ranges:
            return chr(self.ranges[0][0])
        raise ValueError("cannot sample from an empty set")


EMPTY = CharSet()
DIGIT = CharSet.of((48, 57))
WORD = CharSet.of((48, 57), (65, 90), (95, 95), (97, 122))
SPACE = CharSet.of((9, 13), (32, 32))
ALL = CharSet.of((0, MAX_CP))
DOT = CharSet.char("\n").negate()
