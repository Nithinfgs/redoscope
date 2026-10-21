# Changelog

## 0.1.0 - 2026-10-21

Initial release.

- Regex parser for the common Python/JavaScript subset.
- Static detection of exponential and polynomial backtracking candidates.
- Verification by timing CPython `re` and V8 (via Node) in killable subprocesses.
- Python and JavaScript/TypeScript extraction, inline `redoscope: ignore`.
- `scan` and `check` commands; text, JSON and SARIF output; `--fail-on` for CI.
