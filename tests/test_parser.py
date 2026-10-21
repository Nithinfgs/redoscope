import pytest

from redoscope.parser import Alt, Backref, Char, Group, RegexSyntaxError, Repeat, Seq, UnsupportedRegex, parse


def test_quantifiers_and_groups():
    node = parse(r"^(a+)+$")
    assert isinstance(node, Seq)
    rep = node.items[1]
    assert isinstance(rep, Repeat) and rep.min == 1 and rep.max is None
    assert isinstance(rep.body, Group) and isinstance(rep.body.body, Repeat)


def test_braces_and_literal_brace():
    assert parse("a{2,5}").max == 5
    assert parse("a{2,}").max is None
    literal = parse("a{x}")
    assert isinstance(literal, Seq) and len(literal.items) == 4


def test_alternation_and_classes():
    node = parse(r"[a-c]|\d")
    assert isinstance(node, Alt)
    assert node.options[0].chars.contains("b")
    assert node.options[1].chars.contains("7")


def test_lazy_and_possessive():
    assert parse("a+?").lazy
    assert parse("a++").possessive


def test_ignorecase_flag_adds_case_variants():
    assert parse("a", "i").chars.contains("A")
    assert not parse("a").chars.contains("A")


def test_inline_flags_and_named_groups():
    assert isinstance(parse(r"(?P<x>a)(?<y>b)"), Seq)
    assert parse(r"(?i)a").chars.contains("A")


def test_backreference():
    assert isinstance(parse(r"(a)\1").items[1], Backref)


def test_verbose_mode_ignores_whitespace_and_comments():
    node = parse("a +  # comment\n b", "x")
    assert isinstance(node, Seq) and isinstance(node.items[0], Repeat)


def test_negated_class_and_dot():
    assert not parse("[^a]").chars.contains("a")
    assert not parse(".").chars.contains("\n")
    assert parse(".", "s").chars.contains("\n")


def test_syntax_errors():
    for bad in ["(a", "a)", "[a", "*a", "a\\", "a{3,1}", "[z-a]"]:
        with pytest.raises(RegexSyntaxError):
            parse(bad)


def test_unsupported_constructs():
    with pytest.raises(UnsupportedRegex):
        parse(r"(a)(?(1)b|c)")


def test_char_nodes_have_sets():
    assert isinstance(parse("a"), Char)
