"""Email address detector.

A permissive regex finds ``local@domain.tld`` candidates; a second pass
rejects the structural problems the regex cannot express (leading, trailing or
doubled dots in the local part or the domain).
"""
import re

from pii_guard.detectors.base import Match

_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]+"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
    r"(?![A-Za-z0-9\-])"
)


def _structure_valid(email: str) -> bool:
    local, _, domain = email.partition("@")
    for part in (local, domain):
        if part.startswith(".") or part.endswith(".") or ".." in part:
            return False
    return True


def find_email(text: str) -> list:
    """Return every email address in ``text``."""
    return [
        Match(m.group(), m.start(), m.end(), "EMAIL")
        for m in _PATTERN.finditer(text)
        if _structure_valid(m.group())
    ]
