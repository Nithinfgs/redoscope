"""Command line interface."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .extract import RegexSite
from .parser import RegexSyntaxError, UnsupportedRegex
from .report import render_json, render_sarif, render_text
from .scanner import Finding, ScanResult, analyze_pattern, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redoscope",
        description="Find regular expressions that hang your program, and prove it with the real engine.",
    )
    p.add_argument("--version", action="version", version=f"redoscope {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan files or directories (Python, JavaScript, TypeScript)")
    s.add_argument("paths", nargs="+", help="files or directories")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--fail-on", choices=["confirmed", "suspected", "never"], default="confirmed",
                   help="exit 1 when findings of this level exist (default: confirmed)")  # fmt: skip
    s.add_argument(
        "--no-verify", action="store_true", help="static analysis only; every finding is 'suspected'"
    )
    s.add_argument("--budget", type=float, default=4.0, metavar="SECONDS",
                   help="hard time limit per verification attempt (default: 4)")  # fmt: skip
    s.add_argument(
        "--show-suspected", action="store_true", help="also list findings the engine did not confirm"
    )
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="glob to skip (repeatable)")

    c = sub.add_parser("check", help="analyze and verify a single pattern")
    c.add_argument("pattern")
    c.add_argument("--engine", choices=["python", "v8"], default="python")
    c.add_argument("--flags", default="", help="letters from: i m s x")
    c.add_argument("--budget", type=float, default=4.0, metavar="SECONDS")
    c.add_argument("--no-verify", action="store_true")
    c.add_argument("--format", choices=["text", "json"], default="text")
    return p


def _exit_code(result: ScanResult, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if any(f.status == "confirmed" for f in result.findings):
        return 1
    if fail_on == "suspected" and result.findings:
        return 1
    return 0


def _run_check(args: argparse.Namespace) -> int:
    site = RegexSite(
        "<pattern>", 1, 1, args.pattern, args.flags, "python" if args.engine == "python" else "js", ""
    )
    result = ScanResult(files_scanned=0, patterns_checked=1)
    try:
        outcome = analyze_pattern(args.pattern, args.flags, args.engine, not args.no_verify, args.budget)
    except (RegexSyntaxError, UnsupportedRegex) as exc:
        print(f"error: cannot analyze pattern: {exc}", file=sys.stderr)
        return 2
    if outcome:
        status, kind, degree, reason, verdict = outcome
        result.findings.append(
            Finding(
                site, status, kind, degree, reason,
                verdict.detail if verdict else "static analysis only (--no-verify)",
                args.engine,
                verdict.suffix if verdict else "",
                verdict.timings if verdict else [],
                verdict.timed_out if verdict else None,
            )
        )  # fmt: skip
    if args.format == "json":
        print(render_json(result))
    else:
        print(
            render_text(result, color=sys.stdout.isatty())
            if outcome
            else f"no backtracking risk found in {args.pattern!r}"
        )
    return 1 if outcome and outcome[0] == "confirmed" else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        return _run_check(args)
    if args.budget <= 0:
        print("error: --budget must be positive", file=sys.stderr)
        return 2
    import os

    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        print(f"error: no such file or directory: {', '.join(missing)}", file=sys.stderr)
        return 2
    result = scan(args.paths, args.exclude, not args.no_verify, args.budget)
    if args.format == "json":
        print(render_json(result))
    elif args.format == "sarif":
        print(render_sarif(result))
    else:
        show = args.show_suspected or args.no_verify
        print(render_text(result, color=sys.stdout.isatty(), show_suspected=show))
    return _exit_code(result, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
