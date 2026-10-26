"""PII detectors and the overlap-resolving ``detect_all`` entry point."""
from pii_guard.detectors.base import Match
from pii_guard.detectors.credit_card import find_credit_card
from pii_guard.detectors.email import find_email
from pii_guard.detectors.phone import find_phone
from pii_guard.detectors.ssn import find_ssn

# Lower number wins when two detectors claim overlapping text.
PRIORITY = {"CREDIT_CARD": 0, "SSN": 1, "EMAIL": 2, "PHONE": 3}

DETECTORS = (find_credit_card, find_ssn, find_email, find_phone)


def detect_all(text: str) -> list:
    """Run every detector and return non-overlapping matches in text order.

    When two matches overlap, the higher-priority type wins; between equal
    priorities the longer match wins. Without this step an overlapping pair
    would corrupt the text when replacements are applied.
    """
    candidates = [m for detector in DETECTORS for m in detector(text)]
    candidates.sort(key=lambda m: (PRIORITY[m.pii_type], -(m.end - m.start), m.start))
    accepted = []
    for m in candidates:
        if all(m.end <= a.start or m.start >= a.end for a in accepted):
            accepted.append(m)
    return sorted(accepted, key=lambda m: m.start)


__all__ = [
    "Match",
    "detect_all",
    "DETECTORS",
    "PRIORITY",
    "find_credit_card",
    "find_email",
    "find_phone",
    "find_ssn",
]
