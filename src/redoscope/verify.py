"""Prove (or refute) a candidate by timing the real regex engine on an attack string.

Each attempt runs in a separate interpreter with a hard wall-clock limit, so a
genuinely catastrophic pattern can never hang the scan: it is killed and the
timeout itself is the evidence.
"""

from __future__ import annotations

import json
import math
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from .analyzer import Candidate

SUFFIXES = ("!", "\n", "\x00")
PHASE_A = list(range(10, 41, 2))  # additive steps: exponential growth shows up fast
PHASE_B = [500 * 2**k for k in range(0, 8)]  # doubling steps: polynomial growth

_PY_WORKER = r"""
import json, re, sys, time
cfg = json.load(sys.stdin)
flags = 0
for letter in cfg["flags"]:
    flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}.get(letter, 0)
rx = re.compile(cfg["pattern"], flags)
def run(phase, sizes):
    for n in sizes:
        text = cfg["prefix"] + cfg["pump"] * n + cfg["suffix"]
        print(json.dumps({"start": phase, "n": n}), flush=True)
        t0 = time.perf_counter()
        rx.match(text)
        dt = time.perf_counter() - t0
        print(json.dumps({"phase": phase, "n": n, "t": dt}), flush=True)
        if dt > cfg["stop"]:
            return True
    return False
if not run("A", cfg["a"]):
    run("B", cfg["b"])
"""

_JS_WORKER = r"""
const cfg = JSON.parse(process.argv[1]);
const flags = cfg.flags.replace(/[^imsu]/g, "") + "y";
const rx = new RegExp(cfg.pattern, flags);
function run(phase, sizes) {
  for (const n of sizes) {
    const text = cfg.prefix + cfg.pump.repeat(n) + cfg.suffix;
    console.log(JSON.stringify({start: phase, n}));
    const t0 = process.hrtime.bigint();
    rx.lastIndex = 0;
    rx.test(text);
    const dt = Number(process.hrtime.bigint() - t0) / 1e9;
    console.log(JSON.stringify({phase, n, t: dt}));
    if (dt > cfg.stop) return true;
  }
  return false;
}
if (!run("A", cfg.a)) run("B", cfg.b);
"""


@dataclass
class Verdict:
    status: str  # "confirmed" | "suspected" | "error"
    kind: str = ""
    degree: int = 0
    detail: str = ""
    suffix: str = ""
    timings: list[tuple[str, int, float]] = field(default_factory=list)
    timed_out: tuple[str, int] | None = None


def node_available() -> bool:
    return shutil.which("node") is not None


def classify(
    points: list[tuple[str, int, float]], timed_out: tuple[str, int] | None
) -> tuple[str, int, str] | None:
    """Turn raw timings into ("exponential"|"polynomial", degree, explanation) or None."""
    a = [(n, t) for ph, n, t in points if ph == "A"]
    b = [(n, t) for ph, n, t in points if ph == "B"]
    if timed_out and timed_out[0] == "A":
        return "exponential", 0, f"timed out at n={timed_out[1]} after growing steadily"
    significant = [(n, t) for n, t in a if t >= 0.0005]
    if len(significant) >= 3 and significant[-1][1] >= 0.02:
        tail = significant[-4:]
        ratios = [tail[i + 1][1] / tail[i][1] for i in range(len(tail) - 1)]
        mean = math.exp(sum(math.log(r) for r in ratios) / len(ratios))
        if mean >= 1.5:
            return "exponential", 0, f"time grew {mean:.1f}x for every 2 extra characters"
    if len(b) >= 2 or (b and timed_out):
        slopes = []
        for (n1, t1), (n2, t2) in zip(b, b[1:], strict=False):
            if t1 >= 0.002 and t2 > t1:
                slopes.append(math.log(t2 / t1) / math.log(n2 / n1))
        last_t = b[-1][1] if b else 0.0
        if slopes:
            slope = sorted(slopes[-2:])[0]
            if slope >= 1.7 and (last_t >= 0.05 or timed_out):
                return "polynomial", max(2, round(slope)), f"time grows ~n^{slope:.1f}"
        if timed_out and timed_out[0] == "B" and len(b) >= 2 and b[-1][1] >= 0.05:
            return "polynomial", 2, f"timed out at n={timed_out[1]}"
    return None


def _parse(stdout: str) -> tuple[list[tuple[str, int, float]], tuple[str, int] | None]:
    points: list[tuple[str, int, float]] = []
    started: tuple[str, int] | None = None
    for line in stdout.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if "start" in rec:
            started = (rec["start"], rec["n"])
        elif "t" in rec:
            points.append((rec["phase"], rec["n"], rec["t"]))
            started = None
    return points, started


def _run_worker(
    engine: str, pattern: str, flags: str, cand: Candidate, suffix: str, stop_s: float, hard_s: float
) -> tuple[list[tuple[str, int, float]], tuple[str, int] | None, str]:
    cfg = {
        "pattern": pattern,
        "flags": flags,
        "prefix": cand.prefix,
        "pump": cand.pump,
        "suffix": suffix,
        "stop": stop_s,
        "a": PHASE_A,
        "b": PHASE_B,
    }
    if engine == "python":
        cmd = [sys.executable, "-I", "-c", _PY_WORKER]
        stdin: str | None = json.dumps(cfg)
    else:
        node = shutil.which("node")
        assert node
        cmd = [node, "-e", _JS_WORKER, json.dumps(cfg)]
        stdin = None
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=hard_s, check=False)
        out, err, timed_out = proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as exc:
        raw_out, raw_err = exc.stdout, exc.stderr
        out = raw_out.decode() if isinstance(raw_out, bytes) else (raw_out or "")
        err = raw_err.decode() if isinstance(raw_err, bytes) else (raw_err or "")
        timed_out = True
    points, started = _parse(out)
    return points, (started if timed_out else None), err.strip()


def verify(
    pattern: str,
    flags: str,
    candidates: list[Candidate],
    engine: str,
    budget: float = 4.0,
) -> Verdict:
    """Try the candidates against the engine; return the first confirmation, else 'suspected'."""
    if engine == "v8" and not node_available():
        return Verdict("suspected", detail="node not found on PATH, could not verify with V8")
    stop_s = max(0.05, budget / 8)
    last_points: list[tuple[str, int, float]] = []
    for cand in candidates[:3]:
        for suffix in SUFFIXES:
            if suffix == cand.pump:
                continue
            points, started, err = _run_worker(engine, pattern, flags, cand, suffix, stop_s, budget)
            if err and not points and started is None:
                return Verdict("error", detail=err.splitlines()[-1][:200])
            last_points = points
            verdict = classify(points, started)
            if verdict:
                kind, degree, why = verdict
                return Verdict("confirmed", kind, degree, why, suffix, points, started)
    return Verdict(
        "suspected",
        detail="static analysis flagged it but the engine matched in linear time on the tried inputs",
        timings=last_points,
    )
