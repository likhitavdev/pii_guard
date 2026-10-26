"""Span-level precision/recall of the detectors on the labeled corpus.

    python -m evaluation.run_eval
"""
from collections import Counter

from evaluation.corpus import KNOWN_MISSES, MIXED, NEGATIVES, POSITIVES, TEMPLATES
from pii_guard.detectors import detect_all

TYPES = ("SSN", "CREDIT_CARD", "EMAIL", "PHONE")


def _cases():
    """Yield (text, expected) where expected is a Counter of (type, value)."""
    for pii_type, values in POSITIVES.items():
        for value in values:
            for template in TEMPLATES:
                yield template.format(v=value), Counter({(pii_type, value): 1})
    for text in NEGATIVES:
        yield text, Counter()
    for text, expected in MIXED:
        yield text, Counter(expected)


def evaluate() -> dict:
    tp, fp, fn = Counter(), Counter(), Counter()
    n_cases = 0
    for text, expected in _cases():
        n_cases += 1
        found = Counter((m.pii_type, m.value) for m in detect_all(text))
        for key in (expected | found):
            hit = min(expected[key], found[key])
            tp[key[0]] += hit
            fp[key[0]] += found[key] - hit
            fn[key[0]] += expected[key] - hit

    def ratio(a, b):
        return a / b if b else 1.0

    per_type = {}
    for t in TYPES:
        per_type[t] = {
            "tp": tp[t], "fp": fp[t], "fn": fn[t],
            "precision": ratio(tp[t], tp[t] + fp[t]),
            "recall": ratio(tp[t], tp[t] + fn[t]),
        }
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    return {
        "cases": n_cases,
        "per_type": per_type,
        "precision": ratio(T, T + F),
        "recall": ratio(T, T + N),
    }


def known_miss_report() -> list:
    """(type, text, value, caught?) for the documented limitations."""
    out = []
    for pii_type, text, value in KNOWN_MISSES:
        found = {(m.pii_type, m.value) for m in detect_all(text)}
        out.append((pii_type, text, value, (pii_type, value) in found))
    return out


def main() -> None:
    r = evaluate()
    print(f"{r['cases']} labeled cases\n")
    print(f"{'type':<12}{'TP':>4}{'FP':>4}{'FN':>4}{'precision':>11}{'recall':>9}")
    for t, s in r["per_type"].items():
        print(f"{t:<12}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}{s['precision']:>11.3f}{s['recall']:>9.3f}")
    print(f"{'overall':<12}{'':>12}{r['precision']:>11.3f}{r['recall']:>9.3f}")
    print("\nDocumented limitations (real PII that is intentionally not detected):")
    for pii_type, text, value, caught in known_miss_report():
        print(f"  {'caught' if caught else 'MISSED':<7}{pii_type:<12}{text!r}")


if __name__ == "__main__":
    main()
