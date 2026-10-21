from redoscope.extract import extract_js, extract_python


def test_python_calls_and_flags():
    src = (
        "import re\nfrom re import compile as cc\n"
        "A = re.compile(r'a+', re.I | re.S)\nB = cc('b')\nC = re.sub('x', '', s)\n"
    )
    sites, dynamic = extract_python("m.py", src)
    by_pattern = {s.pattern: s for s in sites}
    assert set(by_pattern) == {"a+", "b", "x"}
    assert by_pattern["a+"].flags == "is"
    assert by_pattern["a+"].line == 3
    assert dynamic == 0


def test_python_dynamic_and_concat_and_ignore():
    src = "import re\nre.compile(name)\nre.compile('a' + 'b+')\nre.compile('c+')  # redoscope: ignore\n"
    sites, dynamic = extract_python("m.py", src)
    assert [s.pattern for s in sites] == ["ab+"]
    assert dynamic == 1


def test_python_ignore_on_previous_line():
    src = "import re\n# redoscope: ignore\nre.compile('c+')\n"
    assert extract_python("m.py", src)[0] == []


def test_js_literals_strings_comments():
    src = (
        "const a = /^(x+)+$/i;\n"
        "const s = 'not /a+/ regex';\n"
        "// /commented+/\n"
        "const d = 10 / 2 / 5;\n"
        "const r = new RegExp('^(y+)+$', 'm');\n"
        "function f(q) { return /z+/.test(q); }\n"
    )
    sites, _ = extract_js("m.js", src)
    got = {(s.pattern, s.flags) for s in sites}
    assert ("^(x+)+$", "i") in got
    assert ("^(y+)+$", "m") in got
    assert ("z+", "") in got
    assert not any("commented" in p or "not" in p or p == " 2 " for p, _ in got)


def test_js_class_with_slash_and_dynamic_regexp():
    src = "const a = /[/]+x/;\nconst b = new RegExp(userInput);\n"
    sites, dynamic = extract_js("m.js", src)
    assert [s.pattern for s in sites] == ["[/]+x"]
    assert dynamic == 1


def test_js_unescape_in_new_regexp():
    sites, _ = extract_js("m.js", "new RegExp('\\\\d+\\\\d+')\n")
    assert sites[0].pattern == r"\d+\d+"
