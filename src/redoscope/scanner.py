"""Walk a tree, extract regexes, analyze them and verify the candidates."""

from __future__ import annotations

import fnmatch
import os
import time
from dataclasses import dataclass, field

from .analyzer import find_candidates
from .extract import JS_EXTS, PY_EXTS, RegexSite, extract_js, extract_python
from .parser import RegexSyntaxError, UnsupportedRegex, parse
from .verify import Verdict, verify

DEFAULT_EXCLUDES = (
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
    ".ruff_cache", "dist", "build", "site-packages", ".next", "coverage",
)  # fmt: skip
MAX_FILE_BYTES = 2_000_000


@dataclass
class Finding:
    site: RegexSite
    status: str  # "confirmed" | "suspected"
    kind: str  # "exponential" | "polynomial"
    degree: int
    reason: str
    detail: str
    engine: str
    suffix: str = ""
    timings: list[tuple[str, int, float]] = field(default_factory=list)
    timed_out: tuple[str, int] | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    patterns_checked: int = 0
    dynamic_skipped: int = 0
    skipped: list[tuple[RegexSite, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed: float = 0.0


def iter_files(paths: list[str], excludes: list[str]) -> list[str]:
    skip_dirs = set(DEFAULT_EXCLUDES)
    out: list[str] = []
    for root in paths:
        if os.path.isfile(root):
            out.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs and not d.endswith(".egg-info"))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in excludes):
                    continue
                if os.path.splitext(name)[1] in PY_EXTS | JS_EXTS:
                    out.append(full)
    return out


def engine_for(site: RegexSite) -> str:
    return "python" if site.language == "python" else "v8"


def analyze_pattern(
    pattern: str, flags: str, engine: str, do_verify: bool, budget: float
) -> tuple[str, str, int, str, Verdict | None] | None:
    """Return (status, kind, degree, reason, verdict) or None when the pattern looks safe.

    Raises RegexSyntaxError / UnsupportedRegex when the pattern cannot be modelled.
    """
    root = parse(pattern, flags)
    candidates = find_candidates(root, pattern)
    if not candidates:
        return None
    top = candidates[0]
    if not do_verify:
        return "suspected", top.kind, top.degree, top.reason, None
    verdict = verify(pattern, flags, candidates, engine, budget)
    if verdict.status == "confirmed":
        return "confirmed", verdict.kind, verdict.degree, top.reason, verdict
    if verdict.status == "error":
        raise UnsupportedRegex(f"engine rejected the pattern: {verdict.detail}")
    return "suspected", top.kind, top.degree, top.reason, verdict


def scan(
    paths: list[str],
    excludes: list[str] | None = None,
    do_verify: bool = True,
    budget: float = 4.0,
) -> ScanResult:
    start = time.monotonic()
    result = ScanResult()
    cache: dict[tuple[str, str, str], tuple | None | Exception] = {}
    for path in iter_files(paths, excludes or []):
        ext = os.path.splitext(path)[1]
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                result.errors.append(f"{path}: skipped, larger than {MAX_FILE_BYTES} bytes")
                continue
            with open(path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
            if ext in PY_EXTS:
                sites, dynamic = extract_python(path, source)
            else:
                sites, dynamic = extract_js(path, source)
        except (OSError, SyntaxError, ValueError) as exc:
            result.errors.append(f"{path}: {exc.__class__.__name__}: {exc}")
            continue
        result.files_scanned += 1
        result.dynamic_skipped += dynamic
        for site in sites:
            result.patterns_checked += 1
            engine = engine_for(site)
            key = (engine, site.flags, site.pattern)
            if key not in cache:
                try:
                    cache[key] = analyze_pattern(site.pattern, site.flags, engine, do_verify, budget)
                except (RegexSyntaxError, UnsupportedRegex) as exc:
                    cache[key] = exc
            outcome = cache[key]
            if isinstance(outcome, Exception):
                result.skipped.append((site, str(outcome)))
            elif outcome is not None:
                status, kind, degree, reason, verdict = outcome
                result.findings.append(
                    Finding(
                        site, status, kind, degree, reason,
                        verdict.detail if verdict else "static analysis only (--no-verify)",
                        engine,
                        verdict.suffix if verdict else "",
                        verdict.timings if verdict else [],
                        verdict.timed_out if verdict else None,
                    )
                )  # fmt: skip
    result.findings.sort(
        key=lambda f: (f.status != "confirmed", f.kind != "exponential", f.site.path, f.site.line)
    )
    result.elapsed = time.monotonic() - start
    return result
