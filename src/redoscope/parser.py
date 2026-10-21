"""A tolerant parser for the common subset of Python and JavaScript regex syntax.

It builds a small AST that the analyzer reasons about. It is deliberately not a
full implementation: constructs it cannot model raise ``RegexSyntaxError`` or
``UnsupportedRegex`` and the pattern is reported as skipped, never guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .charset import ALL, DIGIT, DOT, SPACE, WORD, CharSet


class RegexSyntaxError(ValueError):
    pass


class UnsupportedRegex(ValueError):
    pass


@dataclass
class Char:
    chars: CharSet


@dataclass
class Seq:
    items: list[Node] = field(default_factory=list)


@dataclass
class Alt:
    options: list[Node] = field(default_factory=list)


@dataclass
class Group:
    body: Node
    kind: str = "cap"  # cap | nc | look | atomic


@dataclass
class Repeat:
    body: Node
    min: int
    max: int | None  # None means unbounded
    lazy: bool = False
    possessive: bool = False


@dataclass
class Anchor:
    kind: str = "^"


@dataclass
class Backref:
    ref: str = ""


Node = Char | Seq | Alt | Group | Repeat | Anchor | Backref

_ESCAPE_SETS = {
    "d": DIGIT,
    "D": DIGIT.negate(),
    "w": WORD,
    "W": WORD.negate(),
    "s": SPACE,
    "S": SPACE.negate(),
}
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "0": "\0", "a": "\a"}
_FLAG_LETTERS = set("aiLmsux")


class _Parser:
    def __init__(self, pattern: str, ignorecase: bool, dotall: bool, verbose: bool):
        self.src = pattern
        self.pos = 0
        self.ignorecase = ignorecase
        self.dotall = dotall
        self.verbose = verbose
        self.depth = 0

    def peek(self) -> str:
        return self.src[self.pos] if self.pos < len(self.src) else ""

    def take(self) -> str:
        ch = self.src[self.pos]
        self.pos += 1
        return ch

    def eat(self, text: str) -> bool:
        if self.src.startswith(text, self.pos):
            self.pos += len(text)
            return True
        return False

    def charset(self, cs: CharSet) -> Char:
        return Char(cs.with_case_variants() if self.ignorecase else cs)

    def parse(self) -> Node:
        node = self.parse_alt()
        if self.pos != len(self.src):
            raise RegexSyntaxError(f"unbalanced ')' at position {self.pos}")
        return node

    def parse_alt(self) -> Node:
        options = [self.parse_seq()]
        while self.eat("|"):
            options.append(self.parse_seq())
        return options[0] if len(options) == 1 else Alt(options)

    def parse_seq(self) -> Node:
        items: list[Node] = []
        while self.pos < len(self.src) and self.peek() not in "|)":
            if self.verbose and self._skip_verbose():
                continue
            atom = self.parse_atom()
            if atom is None:
                continue
            items.append(self.parse_quantifier(atom))
        return items[0] if len(items) == 1 else Seq(items)

    def _skip_verbose(self) -> bool:
        ch = self.peek()
        if ch.isspace():
            self.pos += 1
            return True
        if ch == "#":
            while self.pos < len(self.src) and self.peek() != "\n":
                self.pos += 1
            return True
        return False

    def parse_quantifier(self, atom: Node) -> Node:
        while True:
            while self.verbose and self.pos < len(self.src) and self._skip_verbose():
                pass
            ch = self.peek()
            if ch == "*":
                lo, hi = 0, None
                self.pos += 1
            elif ch == "+":
                lo, hi = 1, None
                self.pos += 1
            elif ch == "?":
                lo, hi = 0, 1
                self.pos += 1
            elif ch == "{":
                braces = self._try_braces()
                if braces is None:
                    return atom
                lo, hi = braces
            else:
                return atom
            if isinstance(atom, Anchor):
                raise UnsupportedRegex("quantified anchor")
            lazy = possessive = False
            if self.eat("?"):
                lazy = True
            elif self.eat("+"):
                possessive = True
            atom = Repeat(atom, lo, hi, lazy, possessive)

    def _try_braces(self) -> tuple[int, int | None] | None:
        end = self.src.find("}", self.pos)
        if end == -1:
            return None
        inner = self.src[self.pos + 1 : end]
        lo_s, comma, hi_s = inner.partition(",")
        if not (lo_s == "" or lo_s.isdigit()) or not (hi_s == "" or hi_s.isdigit()):
            return None
        if lo_s == "" and (not comma or hi_s == ""):
            return None
        lo = int(lo_s) if lo_s else 0
        hi: int | None = lo if not comma else (int(hi_s) if hi_s else None)
        if hi is not None and hi < lo:
            raise RegexSyntaxError("bad repeat interval")
        self.pos = end + 1
        return lo, hi

    def parse_atom(self) -> Node | None:
        ch = self.take()
        if ch == "(":
            return self.parse_group()
        if ch == "[":
            return self.parse_class()
        if ch == ".":
            return self.charset(ALL if self.dotall else DOT)
        if ch in "^$":
            return Anchor(ch)
        if ch == "\\":
            return self.parse_escape()
        if ch in "*+?":
            raise RegexSyntaxError(f"nothing to repeat at position {self.pos - 1}")
        return self.charset(CharSet.char(ch))

    def parse_group(self) -> Node | None:
        kind = "cap"
        if self.eat("?"):
            if self.eat(":"):
                kind = "nc"
            elif self.eat("=") or self.eat("!"):
                kind = "look"
            elif self.eat("<=") or self.eat("<!"):
                kind = "look"
            elif self.eat(">"):
                kind = "atomic"
            elif self.eat("P="):
                name = self._read_until(")")
                return Backref(name)
            elif self.eat("P<") or self.eat("<"):
                self._read_until(">")
            elif self.eat("#"):
                self._read_until(")")
                return None
            elif self.peek() == "(":
                raise UnsupportedRegex("conditional group")
            else:
                return self._inline_flags()
        self.depth += 1
        body = self.parse_alt()
        self.depth -= 1
        if not self.eat(")"):
            raise RegexSyntaxError("missing ')'")
        return Group(body, kind)

    def _inline_flags(self) -> Node | None:
        start = self.pos
        while self.peek() and (self.peek() in _FLAG_LETTERS or self.peek() == "-"):
            self.pos += 1
        flags = self.src[start : self.pos]
        on = flags.split("-")[0]
        if self.eat(")"):
            if "i" in on:
                self.ignorecase = True
            if "s" in on:
                self.dotall = True
            if "x" in on:
                self.verbose = True
            return None
        if self.eat(":"):
            if "i" in on:
                self.ignorecase = True
            self.depth += 1
            body = self.parse_alt()
            self.depth -= 1
            if not self.eat(")"):
                raise RegexSyntaxError("missing ')'")
            return Group(body, "nc")
        raise UnsupportedRegex(f"unsupported group syntax near position {start}")

    def _read_until(self, stop: str) -> str:
        end = self.src.find(stop, self.pos)
        if end == -1:
            raise RegexSyntaxError(f"missing {stop!r}")
        text = self.src[self.pos : end]
        self.pos = end + 1
        return text

    def parse_escape(self) -> Node:
        if self.pos >= len(self.src):
            raise RegexSyntaxError("trailing backslash")
        ch = self.take()
        if ch in _ESCAPE_SETS:
            return self.charset(_ESCAPE_SETS[ch])
        if ch in "bBAZzG":
            return Anchor("\\" + ch)
        if ch in "123456789":
            digits = ch
            while self.peek().isdigit() and len(digits) < 2:
                digits += self.take()
            return Backref(digits)
        if ch == "k":
            if self.eat("<"):
                return Backref(self._read_until(">"))
            return self.charset(CharSet.char("k"))
        if ch in "pP":
            if self.eat("{"):
                self._read_until("}")
            return self.charset(WORD if ch == "p" else WORD.negate())
        return self.charset(CharSet.char(self._escape_char(ch)))

    def _escape_char(self, ch: str) -> str:
        if ch in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[ch]
        if ch == "x":
            return self._hex(2)
        if ch == "u":
            if self.eat("{"):
                return chr(int(self._read_until("}"), 16))
            return self._hex(4)
        if ch == "c" and self.peek().isalpha():
            return chr(ord(self.take().upper()) % 32)
        return ch

    def _hex(self, n: int) -> str:
        digits = self.src[self.pos : self.pos + n]
        if len(digits) != n or any(d not in "0123456789abcdefABCDEF" for d in digits):
            raise RegexSyntaxError("bad hex escape")
        self.pos += n
        return chr(int(digits, 16))

    def parse_class(self) -> Node:
        negate = self.eat("^")
        result = CharSet()
        first = True
        while True:
            if self.pos >= len(self.src):
                raise RegexSyntaxError("unterminated character class")
            ch = self.take()
            if ch == "]" and not first:
                break
            first = False
            lo = self._class_atom(ch)
            if isinstance(lo, CharSet):
                result = result.union(lo)
                continue
            if self.peek() == "-" and self.src[self.pos + 1 : self.pos + 2] not in ("]", ""):
                self.pos += 1
                hi = self._class_atom(self.take())
                if isinstance(hi, CharSet):
                    result = result.union(CharSet.char(lo)).union(CharSet.char("-")).union(hi)
                    continue
                if ord(hi) < ord(lo):
                    raise RegexSyntaxError("bad character range")
                result = result.union(CharSet.of((ord(lo), ord(hi))))
            else:
                result = result.union(CharSet.char(lo))
        if self.ignorecase:
            result = result.with_case_variants()
        return Char(result.negate() if negate else result)

    def _class_atom(self, ch: str) -> CharSet | str:
        if ch != "\\":
            return ch
        if self.pos >= len(self.src):
            raise RegexSyntaxError("trailing backslash")
        esc = self.take()
        if esc in _ESCAPE_SETS:
            return _ESCAPE_SETS[esc]
        if esc == "b":
            return "\b"
        if esc in "pP":
            if self.eat("{"):
                self._read_until("}")
            return WORD if esc == "p" else WORD.negate()
        return self._escape_char(esc)


def parse(pattern: str, flags: str = "") -> Node:
    """Parse ``pattern``. ``flags`` uses letters: i (ignore case), s (dotall), x (verbose)."""
    return _Parser(pattern, "i" in flags, "s" in flags, "x" in flags).parse()
