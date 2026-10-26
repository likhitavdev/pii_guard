"""US Social Security Number detector.

Matches ``AAA-GG-SSSS`` (dashes or single spaces, used consistently) and then
applies the structural rules the SSA publishes: the area number cannot be 000,
666 or 900-999, the group cannot be 00 and the serial cannot be 0000.

Bare nine-digit strings are deliberately *not* matched: without a separator
they are indistinguishable from order numbers, zip+4 values and so on.
"""
import re

from pii_guard.detectors.base import Match

_PATTERN = re.compile(r"(?<![\d-])(\d{3})([- ])(\d{2})\2(\d{4})(?![\d-])")


def _structurally_valid(area: str, group: str, serial: str) -> bool:
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def find_ssn(text: str) -> list:
    """Return every structurally valid SSN in ``text``."""
    return [
        Match(m.group(), m.start(), m.end(), "SSN")
        for m in _PATTERN.finditer(text)
        if _structurally_valid(m.group(1), m.group(3), m.group(4))
    ]
