import pytest

from redoscope.analyzer import find_candidates
from redoscope.parser import parse


def kinds(pattern, flags=""):
    return [(c.kind, c.degree) for c in find_candidates(parse(pattern, flags))]


@pytest.mark.parametrize(
    "pattern",
    [r"^(a+)+$", r"(x+x+)+y", r"(a|aa)+$", r"(a|a)*b", r"^(\w+\s?)+$", r"^(a*)*$", r"(a|[ab])+c"],
)
def test_exponential_candidates(pattern):
    assert kinds(pattern)[0][0] == "exponential"


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[a-z]+$",
        r"^(\d+\.)+\d+$",
        r'^"([^"\\]|\\.)*"$',
        r"^(a+)++$",
        r"^(?>a+)+$",
        r"^(ab|cd)+$",
        r"^(?:\s*,\s*\w+)*$",
        r"^\w+@\w+\.com$",
        r"(a|b)+",
    ],
)
def test_safe_patterns_have_no_candidates(pattern):
    assert kinds(pattern) == []


def test_polynomial_adjacent_loops():
    assert kinds(r"^\d+\d+$") == [("polynomial", 2)]
    assert kinds(r".*.*=.*")[0] == ("polynomial", 2)
    assert kinds(r"\d+\d*\d+")[0] == ("polynomial", 3)


def test_polynomial_across_nullable_gap():
    assert kinds(r"(\w+)\s*(\w+)") == [("polynomial", 2)]


def test_disjoint_loops_are_not_polynomial():
    assert kinds(r"\d+\s+\w") == []


def test_prefix_reaches_the_loop():
    cand = find_candidates(parse(r"^id:(a+)+$"))[0]
    assert cand.prefix == "id:"
    assert cand.pump == "a"
