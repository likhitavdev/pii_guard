"""
phone.py — Phone Number Detector

YOUR regex pattern from phone_number_validation.py — unchanged.
"""
import re
from pii_guard.detectors.base import Match


def find_phone(text: str) -> list:
    """
    Find all US phone numbers in the given text.
    YOUR pattern handles: (732) 880-9321, 732-880-9321, +1-732-880-9321
    """
    pattern = r"\b(\+1[-\s]?)?\(?[2-9]\d{2}\)?[-\s]?[2-9]\d{2}[-\s]?\d{4}\b"

    return [
        Match(value=m.group(), start=m.start(), end=m.end(), pii_type="PHONE")
        for m in re.finditer(pattern, text)
    ]
