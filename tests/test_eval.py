"""Keeps the labeled corpus honest: scores may not regress."""
from evaluation.run_eval import evaluate, known_miss_report


def test_no_regression_on_labeled_corpus():
    r = evaluate()
    assert r["cases"] >= 130
    assert r["precision"] >= 0.98
    assert r["recall"] >= 0.98
    for t, s in r["per_type"].items():
        assert s["tp"] > 0, t


def test_documented_limitations_are_still_documented():
    # If one of these starts being caught, update the README's limitations list.
    assert not any(caught for *_, caught in known_miss_report())
