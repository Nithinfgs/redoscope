"""Static detection of regex shapes that can backtrack badly.

The analyzer only nominates *candidates*. Each candidate carries a concrete attack
recipe (prefix, pump character) that ``verify`` then runs against the real engine.
"""

from __future__ import annotations

from dataclasses import dataclass

from .charset import EMPTY, CharSet
from .parser import Alt, Anchor, Backref, Char, Group, Node, Repeat, Seq

INF = float("inf")


@dataclass
class Candidate:
    kind: str  # "exponential" | "polynomial"
    degree: int  # 0 for exponential, otherwise the suspected polynomial degree
    reason: str
    prefix: str
    pump: str
    loop_source: str


def lengths(node: Node) -> tuple[int, float]:
    if isinstance(node, Char):
        return 1, 1
    if isinstance(node, (Anchor,)):
        return 0, 0
    if isinstance(node, Backref):
        return 0, INF
    if isinstance(node, Group):
        return (0, 0) if node.kind == "look" else lengths(node.body)
    if isinstance(node, Seq):
        lo, hi = 0, 0.0
        for item in node.items:
            a, b = lengths(item)
            lo += a
            hi += b
        return lo, hi
    if isinstance(node, Alt):
        spans = [lengths(o) for o in node.options]
        return min(s[0] for s in spans), max(s[1] for s in spans)
    lo, hi = lengths(node.body)
    top = INF if node.max is None else node.max
    return lo * node.min, (0 if hi == 0 else hi * top)


def nullable(node: Node) -> bool:
    return lengths(node)[0] == 0


def first(node: Node) -> CharSet:
    if isinstance(node, Char):
        return node.chars
    if isinstance(node, (Anchor, Backref)):
        return EMPTY
    if isinstance(node, Group):
        return EMPTY if node.kind == "look" else first(node.body)
    if isinstance(node, Repeat):
        return first(node.body)
    if isinstance(node, Alt):
        out = EMPTY
        for option in node.options:
            out = out.union(first(option))
        return out
    out = EMPTY
    for item in node.items:
        out = out.union(first(item))
        if not nullable(item):
            break
    return out


def last(node: Node) -> CharSet:
    if isinstance(node, Char):
        return node.chars
    if isinstance(node, (Anchor, Backref)):
        return EMPTY
    if isinstance(node, Group):
        return EMPTY if node.kind == "look" else last(node.body)
    if isinstance(node, Repeat):
        return last(node.body)
    if isinstance(node, Alt):
        out = EMPTY
        for option in node.options:
            out = out.union(last(option))
        return out
    out = EMPTY
    for item in reversed(node.items):
        out = out.union(last(item))
        if not nullable(item):
            break
    return out


def consumed(node: Node) -> CharSet:
    if isinstance(node, Char):
        return node.chars
    if isinstance(node, (Anchor, Backref)):
        return EMPTY
    if isinstance(node, Group):
        return EMPTY if node.kind == "look" else consumed(node.body)
    if isinstance(node, Repeat):
        return consumed(node.body)
    parts = node.options if isinstance(node, Alt) else node.items
    out = EMPTY
    for part in parts:
        out = out.union(consumed(part))
    return out


def sample(node: Node) -> str:
    """A short string the node matches (best effort; verification is the judge)."""
    if isinstance(node, Char):
        return node.chars.sample() if not node.chars.is_empty() else ""
    if isinstance(node, (Anchor, Backref)):
        return ""
    if isinstance(node, Group):
        return "" if node.kind == "look" else sample(node.body)
    if isinstance(node, Repeat):
        return sample(node.body) * node.min
    if isinstance(node, Alt):
        return sample(min(node.options, key=lambda o: lengths(o)[0]))
    return "".join(sample(i) for i in node.items)


def has_unbounded(node: Node) -> bool:
    if isinstance(node, Repeat):
        return (node.max is None and lengths(node.body)[1] > 0) or has_unbounded(node.body)
    if isinstance(node, Group):
        return node.kind != "atomic" and has_unbounded(node.body)
    if isinstance(node, Seq):
        return any(has_unbounded(i) for i in node.items)
    if isinstance(node, Alt):
        return any(has_unbounded(o) for o in node.options)
    return False


Path = list[tuple[Node, int]]


def _prefix(path: Path) -> str:
    out = ""
    for parent, idx in path:
        if isinstance(parent, Seq):
            out += "".join(sample(i) for i in parent.items[:idx])
    return out


def _overlapping_single_chars(alt: Alt) -> CharSet:
    singles = [o for o in alt.options if isinstance(o, Char)]
    overlap = EMPTY
    for i, a in enumerate(singles):
        for b in singles[i + 1 :]:
            overlap = overlap.union(a.chars.intersect(b.chars))
    return overlap


def _option_start_overlap(alt: Alt) -> CharSet:
    overlap = EMPTY
    for i, a in enumerate(alt.options):
        for b in alt.options[i + 1 :]:
            overlap = overlap.union(first(a).intersect(first(b)))
    return overlap


def _loop_candidate(rep: Repeat, path: Path, source: str) -> Candidate | None:
    body = rep.body
    lo, hi = lengths(body)
    if hi == 0 or (isinstance(body, Group) and body.kind == "atomic"):
        return None
    pump_set = EMPTY
    reason = ""
    if lo == 0 and has_unbounded(body):
        pump_set = consumed(body)
        reason = "the repeated group can match the empty string and also contains an unbounded loop"
    else:
        inner = body.body if isinstance(body, Group) else body
        boundary = first(body).intersect(last(body))
        if isinstance(inner, Alt):
            single = _overlapping_single_chars(inner)
            if not single.is_empty():
                pump_set = single
                reason = "alternatives inside the loop can match the same character"
            elif lo != hi:
                shared = _option_start_overlap(inner).intersect(boundary)
                if not shared.is_empty():
                    pump_set = shared
                    reason = (
                        "alternatives of different lengths inside the loop overlap at the iteration boundary"
                    )
        if pump_set.is_empty() and lo != hi and has_unbounded(body) and not boundary.is_empty():
            pump_set = boundary
            reason = "nested unbounded loops: the same input can be split between iterations in many ways"
    if pump_set.is_empty():
        return None
    return Candidate("exponential", 0, reason, _prefix(path), pump_set.sample(), source)


def _flatten(items: list[Node]) -> list[Node]:
    out: list[Node] = []
    for item in items:
        if isinstance(item, Group) and item.kind in ("cap", "nc"):
            body = item.body
            out.extend(_flatten(body.items if isinstance(body, Seq) else [body]))
        elif isinstance(item, Seq):
            out.extend(_flatten(item.items))
        else:
            out.append(item)
    return out


def _simple_loop(node: Node) -> bool:
    return (
        isinstance(node, Repeat) and node.max is None and not node.possessive and isinstance(node.body, Char)
    )


def _poly_candidates(seq: Seq, path: Path, source: str) -> list[Candidate]:
    flat = _flatten(seq.items)
    found: list[Candidate] = []
    i = 0
    while i < len(flat):
        item = flat[i]
        if not _simple_loop(item):
            i += 1
            continue
        pump = consumed(item)
        run = [item]
        j = i + 1
        while j < len(flat):
            cur = flat[j]
            if _simple_loop(cur) and not pump.intersect(consumed(cur)).is_empty():
                pump = pump.intersect(consumed(cur))
                run.append(cur)
            elif not nullable(cur) or isinstance(cur, Backref):
                break
            j += 1
        if len(run) >= 2:
            before = "".join(sample(x) for x in flat[:i])
            found.append(
                Candidate(
                    "polynomial",
                    len(run),
                    f"{len(run)} adjacent unbounded loops can match the same characters",
                    _prefix(path) + before,
                    pump.sample(),
                    source,
                )
            )
            i = j
        else:
            i += 1
    return found


def find_candidates(root: Node, source: str = "") -> list[Candidate]:
    candidates: list[Candidate] = []

    def walk(node: Node, path: Path, atomic: bool) -> None:
        if isinstance(node, Repeat):
            if node.max is None and not node.possessive and not atomic:
                cand = _loop_candidate(node, path, source)
                if cand:
                    candidates.append(cand)
            walk(node.body, path + [(node, 0)], atomic or node.possessive)
        elif isinstance(node, Group):
            walk(node.body, path + [(node, 0)], atomic or node.kind == "atomic")
        elif isinstance(node, Seq):
            if not atomic:
                candidates.extend(_poly_candidates(node, path, source))
            for idx, item in enumerate(node.items):
                walk(item, path + [(node, idx)], atomic)
        elif isinstance(node, Alt):
            for idx, option in enumerate(node.options):
                walk(option, path + [(node, idx)], atomic)

    walk(root, [], False)
    if not isinstance(root, Seq):
        candidates.extend(_poly_candidates(Seq([root]), [], source))
    unique = {(c.kind, c.degree, c.prefix, c.pump): c for c in candidates}
    return sorted(unique.values(), key=lambda c: (c.kind != "exponential", -c.degree))
