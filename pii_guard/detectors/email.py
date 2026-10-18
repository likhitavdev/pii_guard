"""
email.py — Email Detector

YOUR email validation logic from validation.py adapted here.
Using regex for detection (more reliable for finding email in text),
then applying your structural validation as a second check.
"""
import re
from pii_guard.detectors.base import Match


def _email_structure_valid(email: str) -> bool:
    """
    YOUR validation logic from validation.py — checks @ position and domain structure.
    """
    if "@" not in email:
        return False

    at_index = email.index("@")
    if at_index <= 0 or at_index >= len(email) - 1:
        return False

    domain = email[at_index + 1:]
    if "." not in domain:
        return False

    dot_pos = domain.index(".")
    return 0 < dot_pos < len(domain) - 1


def find_email(text: str) -> list:
    """
    Find all email addresses in the given text.
    """
    # Regex finds anything that looks like user@domain.tld
    pattern = r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"

    matches = []
    for m in re.finditer(pattern, text):
        if _email_structure_valid(m.group()):
            matches.append(
                Match(value=m.group(), start=m.start(), end=m.end(), pii_type="EMAIL")
            )
    return matches
