"""Payment card detector.

Two stages, so that look-alike numbers (order ids, timestamps) are discarded:

1. Regexes find card-shaped digit runs: 4-4-4-4 groupings, the 4-6-5 Amex
   grouping, or an unbroken run of 13-19 digits.
2. A candidate is kept only if its issuer prefix/length is plausible
   (Visa, Mastercard, Amex, Discover, Diners, JCB) *and* it passes the Luhn
   checksum.
"""
import re

from pii_guard.detectors.base import Match

_PATTERNS = (
    re.compile(r"(?<![\d-])\d{4}([ -]?)\d{4}\1\d{4}\1\d{4}(?![\d-])"),
    re.compile(r"(?<![\d-])3[47]\d{2}([ -]?)\d{6}\1\d{5}(?![\d-])"),
    re.compile(r"(?<![\d-])\d{13,19}(?![\d-])"),
)

# (issuer prefix regex, allowed lengths)
_ISSUERS = (
    (re.compile(r"4"), {13, 16, 19}),  # Visa
    (re.compile(r"5[1-5]|2(?:2[2-9]\d|[3-6]\d\d|7[01]\d|720)"), {16}),  # Mastercard
    (re.compile(r"3[47]"), {15}),  # American Express
    (re.compile(r"6011|65|64[4-9]"), {16, 17, 18, 19}),  # Discover
    (re.compile(r"30[0-5]|36|38"), {14}),  # Diners Club
    (re.compile(r"35"), {16, 17, 18, 19}),  # JCB
)


def luhn_valid(digits: str) -> bool:
    """Luhn checksum over a string of digits (any length)."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _plausible_issuer(digits: str) -> bool:
    return any(p.match(digits) and len(digits) in lengths for p, lengths in _ISSUERS)


def find_credit_card(text: str) -> list:
    """Return every Luhn-valid card number with a plausible issuer prefix."""
    spans = {}
    for pattern in _PATTERNS:
        for m in pattern.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if _plausible_issuer(digits) and luhn_valid(digits):
                spans[(m.start(), m.end())] = m.group()
    return [
        Match(value, start, end, "CREDIT_CARD")
        for (start, end), value in sorted(spans.items())
    ]
