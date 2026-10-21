"""Text, JSON and SARIF renderers."""

from __future__ import annotations

import json
import os

from . import __version__
from .scanner import Finding, ScanResult

FIX_HINT = (
    "make iterations unambiguous (e.g. `(a+)+` -> `a+`, `(\\w+\\s?)+` -> `\\w+(?:\\s\\w+)*\\s?`), "
    "use an atomic group or possessive quantifier where the engine supports it "
    "(Python 3.11+), cap the input length, or switch to a linear-time engine such as RE2"
)


def _proof(f: Finding) -> str:
    if f.status != "confirmed":
        return f.detail
    top = max(f.timings, key=lambda p: p[2], default=None)
    parts = [f"{f.detail}"]
    if top:
        parts.append(f"n={top[1]} took {top[2] * 1000:.0f} ms")
    if f.timed_out:
        parts.append(f"killed after the hard limit while running n={f.timed_out[1]}")
    return "; ".join(parts) + f" ({f.engine}, attack suffix {f.suffix!r})"


def _label(f: Finding) -> str:
    if f.kind == "exponential":
        return "exponential"
    return f"polynomial (degree {f.degree})"


def render_text(result: ScanResult, color: bool = False, show_suspected: bool = True) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    lines = [
        f"redoscope {__version__}: {result.files_scanned} files, {result.patterns_checked} regexes, "
        f"{result.elapsed:.1f}s"
    ]
    confirmed = [f for f in result.findings if f.status == "confirmed"]
    suspected = [f for f in result.findings if f.status != "confirmed"]
    shown = result.findings if show_suspected else confirmed
    for f in shown:
        tag = paint("CONFIRMED", "1;31") if f.status == "confirmed" else paint("suspected", "33")
        lines.append("")
        lines.append(f"{tag}  {_label(f)}  {f.site.path}:{f.site.line}:{f.site.col}")
        lines.append(f"  pattern: {f.site.pattern}")
        lines.append(f"  why:     {f.reason}")
        lines.append(f"  proof:   {_proof(f)}")
    lines.append("")
    if confirmed:
        lines.append(f"How to fix: {FIX_HINT}.")
        lines.append("")
    summary = f"{len(confirmed)} confirmed, {len(suspected)} suspected"
    if suspected and not show_suspected:
        summary += " (static-only hits the engine did not slow down on; show them with --show-suspected)"
    lines.append(summary)
    if result.skipped:
        lines.append(f"{len(result.skipped)} pattern(s) could not be modelled and were skipped")
    if result.dynamic_skipped:
        lines.append(f"{result.dynamic_skipped} dynamically built pattern(s) were not analyzed")
    for err in result.errors:
        lines.append(f"warning: {err}")
    return "\n".join(lines)


def _finding_dict(f: Finding) -> dict:
    return {
        "path": f.site.path,
        "line": f.site.line,
        "column": f.site.col,
        "pattern": f.site.pattern,
        "flags": f.site.flags,
        "engine": f.engine,
        "status": f.status,
        "kind": f.kind,
        "degree": f.degree,
        "reason": f.reason,
        "detail": f.detail,
        "attack_suffix": f.suffix,
        "timings": [{"phase": p, "n": n, "seconds": t} for p, n, t in f.timings],
        "timed_out_at": f.timed_out[1] if f.timed_out else None,
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "redoscope",
            "version": __version__,
            "files_scanned": result.files_scanned,
            "patterns_checked": result.patterns_checked,
            "dynamic_skipped": result.dynamic_skipped,
            "skipped": [{"path": s.path, "line": s.line, "reason": r} for s, r in result.skipped],
            "errors": result.errors,
            "findings": [_finding_dict(f) for f in result.findings],
        },
        indent=2,
    )


def render_sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": "REDOS001",
            "name": "ExponentialBacktracking",
            "shortDescription": {"text": "Regular expression with exponential backtracking"},
            "helpUri": "https://cwe.mitre.org/data/definitions/1333.html",
        },
        {
            "id": "REDOS002",
            "name": "PolynomialBacktracking",
            "shortDescription": {"text": "Regular expression with polynomial backtracking"},
            "helpUri": "https://cwe.mitre.org/data/definitions/1333.html",
        },
    ]
    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": "REDOS001" if f.kind == "exponential" else "REDOS002",
                "level": "error" if f.status == "confirmed" else "warning",
                "message": {"text": f"{f.status}: {f.reason}. {f.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": os.path.relpath(f.site.path).replace(os.sep, "/")},
                            "region": {"startLine": f.site.line, "startColumn": f.site.col},
                        }
                    }
                ],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "redoscope", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
