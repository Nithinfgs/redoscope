import shutil

import pytest

from redoscope.analyzer import find_candidates
from redoscope.parser import parse
from redoscope.verify import classify, verify


def run(pattern, engine="python", flags=""):
    return verify(pattern, flags, find_candidates(parse(pattern, flags)), engine, budget=4.0)


def test_exponential_is_confirmed():
    v = run(r"^(a+)+$")
    assert v.status == "confirmed" and v.kind == "exponential"


def test_polynomial_is_confirmed():
    v = run(r"^\d+\d+$")
    assert v.status == "confirmed" and v.kind == "polynomial" and v.degree >= 2


def test_false_positive_is_refuted():
    v = run(r"(a|ab)+$")
    assert v.status == "suspected"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_v8_engine_confirms():
    assert run(r"^(a+)+$", "v8").status == "confirmed"


def test_classify_exponential_from_ratios():
    points = [("A", n, 0.0006 * 2 ** (i)) for i, n in enumerate(range(10, 30, 2))]
    result = classify(points, None)
    assert result and result[0] == "exponential"


def test_classify_polynomial_from_slope():
    points = [("B", n, 1e-8 * n * n) for n in (500, 1000, 2000, 4000, 8000, 16000)]
    result = classify(points, None)
    assert result and result[0] == "polynomial" and result[1] == 2


def test_classify_linear_is_clean():
    points = [("A", n, 1e-6 * n) for n in range(10, 40, 2)]
    points += [("B", n, 1e-6 * n) for n in (500, 1000, 2000, 4000, 8000)]
    assert classify(points, None) is None


def test_classify_timeout_in_phase_a():
    assert classify([("A", 10, 0.001)], ("A", 14))[0] == "exponential"


def test_engine_rejection_is_reported():
    from redoscope.analyzer import Candidate

    cand = Candidate("exponential", 0, "x", "", "a", "")
    v = verify("(", "", [cand], "python")
    assert v.status == "error"
