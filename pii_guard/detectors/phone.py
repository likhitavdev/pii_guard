"""US/NANP phone number detector.

Only *formatted* numbers are matched: separators between the groups, a
parenthesised area code, or a ``+1`` prefix. A bare ten-digit run such as
``2345678901`` is far more likely to be an order or account id than a phone
number, so it is left alone (see the README's limitations section).

Area code and exchange must start with 2-9, as the North American Numbering
Plan requires.
"""
import re

from pii_guard.detectors.base import Match

_PREFIX = r"(?:\+?1[-.\s]?)?"
_PATTERNS = (
    # 732-555-0101, 732.555.0101, 732 555 0101, 1-732-555-0101
    re.compile(r"(?<!\w)" + _PREFIX + r"[2-9]\d{2}([-.\s])[2-9]\d{2}\1\d{4}(?![\w-])"),
    # (732) 555-0101, (732)555-0101
    re.compile(r"(?<!\w)" + _PREFIX + r"\([2-9]\d{2}\)[-.\s]?[2-9]\d{2}[-.\s]?\d{4}(?![\w-])"),
    # +17325550101, +1 732 5550101
    re.compile(r"(?<!\w)\+1[-.\s]?[2-9]\d{2}[-.\s]?[2-9]\d{2}[-.\s]?\d{4}(?![\w-])"),
)


def find_phone(text: str) -> list:
    """Return every formatted US phone number in ``text``."""
    spans = {}
    for pattern in _PATTERNS:
        for m in pattern.finditer(text):
            spans[(m.start(), m.end())] = m.group()
    return [
        Match(value, start, end, "PHONE")
        for (start, end), value in sorted(spans.items())
    ]
