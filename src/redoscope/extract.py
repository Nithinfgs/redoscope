"""Find regular expressions in Python and JavaScript/TypeScript source files."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

PY_EXTS = {".py"}
JS_EXTS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
IGNORE_MARK = "redoscope: ignore"

_PY_FUNCS = {
    "compile": 1,
    "match": 2,
    "search": 2,
    "fullmatch": 2,
    "split": 3,
    "sub": 4,
    "subn": 4,
    "findall": 2,
    "finditer": 2,
}
_PY_FLAG_LETTERS = {
    "I": "i",
    "IGNORECASE": "i",
    "M": "m",
    "MULTILINE": "m",
    "S": "s",
    "DOTALL": "s",
    "X": "x",
    "VERBOSE": "x",
}


@dataclass(frozen=True)
class RegexSite:
    path: str
    line: int
    col: int
    pattern: str
    flags: str  # letters from "imsx"
    language: str  # "python" | "js"
    snippet: str


def _ignored(lines: list[str], line: int) -> bool:
    for idx in (line - 1, line - 2):
        if 0 <= idx < len(lines) and IGNORE_MARK in lines[idx]:
            return True
    return False


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _const_str(node.left), _const_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _flag_letters(nodes: list[ast.expr]) -> str:
    found = ""
    for root in nodes:
        for sub in ast.walk(root):
            name = None
            if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                if sub.value.id in ("re", "regex"):
                    name = sub.attr
            elif isinstance(sub, ast.Name):
                name = sub.id
            if name in _PY_FLAG_LETTERS:
                found += _PY_FLAG_LETTERS[name]
    return "".join(sorted(set(found)))


def extract_python(path: str, source: str) -> tuple[list[RegexSite], int]:
    """Return (sites, number_of_dynamic_patterns_skipped). Raises SyntaxError on bad files."""
    tree = ast.parse(source, filename=path)
    lines = source.splitlines()
    imported: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("re", "regex"):
            imported.update({a.asname or a.name: a.name for a in node.names if a.name in _PY_FUNCS})
    sites: list[RegexSite] = []
    dynamic = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = None
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in ("re", "regex")
        ):
            name = func.attr
        elif isinstance(func, ast.Name) and func.id in imported:
            name = imported[func.id]
        if name not in _PY_FUNCS or not node.args:
            continue
        pattern = _const_str(node.args[0])
        if pattern is None:
            if not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, bytes)):
                dynamic += 1
            continue
        if _ignored(lines, node.lineno):
            continue
        flag_args = list(node.args[_PY_FUNCS[name] :]) + [k.value for k in node.keywords]
        sites.append(
            RegexSite(
                path,
                node.args[0].lineno,
                node.args[0].col_offset + 1,
                pattern,
                _flag_letters(flag_args),
                "python",
                lines[node.args[0].lineno - 1].strip()[:160],
            )
        )
    return sites, dynamic


_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _js_unescape(body: str) -> str | None:
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            return None
        esc = body[i]
        if esc in _ESC:
            out.append(_ESC[esc])
            i += 1
        elif esc == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 1 : i + 3]):
            out.append(chr(int(body[i + 1 : i + 3], 16)))
            i += 3
        elif esc == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", body[i + 1 : i + 5]):
            out.append(chr(int(body[i + 1 : i + 5], 16)))
            i += 5
        else:
            out.append(esc)
            i += 1
    return "".join(out)


_REGEX_PREV_KEYWORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else",
}  # fmt: skip
_NEW_REGEXP = re.compile(r"""\bRegExp\s*\(\s*(["'])((?:\\.|(?!\1).)*)\1\s*(?:,\s*(["'])([a-z]*)\3)?""")


_DYNAMIC_REGEXP = re.compile(r"""\bRegExp\s*\(\s*[^\s"')]""")


def _regex_allowed(prev_token: str) -> bool:
    if not prev_token:
        return True
    if prev_token in _REGEX_PREV_KEYWORDS:
        return True
    if prev_token[-1].isalnum() or prev_token[-1] in "_$":
        return False
    return prev_token not in (")", "]", "}")


def extract_js(path: str, source: str) -> tuple[list[RegexSite], int]:
    """Scan JS/TS with a small tokenizer that tracks strings, comments and regex literals."""
    lines = source.splitlines()
    sites: list[RegexSite] = []
    n = len(source)
    i = 0
    line = 1
    line_start = 0
    prev = ""
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
            line_start = i + 1
            i += 1
            continue
        if ch.isspace():
            i += 1
            continue
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            line += source.count("\n", i, end)
            i = end
            continue
        if ch in "\"'`":
            j = i + 1
            while j < n and source[j] != ch:
                if source[j] == "\\":
                    j += 1
                elif source[j] == "\n" and ch != "`":
                    break
                j += 1
            line += source.count("\n", i, j)
            prev = ch
            i = j + 1
            continue
        if ch == "/" and _regex_allowed(prev):
            j = i + 1
            in_class = False
            while j < n and source[j] != "\n":
                c = source[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    break
                j += 1
            if j < n and source[j] == "/":
                body = source[i + 1 : j]
                k = j + 1
                while k < n and source[k].isalpha():
                    k += 1
                flags = "".join(sorted(set(source[j + 1 : k]) & set("ims")))
                if body and not _ignored(lines, line):
                    sites.append(
                        RegexSite(
                            path, line, i - line_start + 1, body, flags, "js", lines[line - 1].strip()[:160]
                        )
                    )
                prev = "regex"
                i = k
                continue
        if ch.isalnum() or ch in "_$":
            j = i
            while j < n and (source[j].isalnum() or source[j] in "_$"):
                j += 1
            prev = source[i:j]
            i = j
            continue
        prev = ch
        i += 1
    dynamic = len(_DYNAMIC_REGEXP.findall(source))
    for m in _NEW_REGEXP.finditer(source):
        decoded = _js_unescape(m.group(2))
        ln = source.count("\n", 0, m.start()) + 1
        if decoded is None or _ignored(lines, ln):
            continue
        flags = "".join(sorted(set(m.group(4) or "") & set("ims")))
        col = m.start() - (source.rfind("\n", 0, m.start()) + 1) + 1
        sites.append(RegexSite(path, ln, col, decoded, flags, "js", lines[ln - 1].strip()[:160]))
    return sites, dynamic
