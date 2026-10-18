"""
credit_card.py — Credit Card Detector

YOUR Luhn algorithm from credit_card_validation.py preserved exactly.
Added: find_credit_card() that scans text, finds card-shaped numbers,
then validates each one with Luhn before returning it as a real match.

Two-step process (same as your original design):
  Step 1 — regex finds anything that LOOKS like a credit card
  Step 2 — Luhn validates it's a REAL credit card number
"""
import re
from pii_guard.detectors.base import Match


def _luhn_valid(card_number: str) -> bool:
    """
    YOUR Luhn algorithm from credit_card_validation.py — unchanged.
    True if the card passes the checksum, False otherwise.
    """
    digits_only = re.sub(r"\D", "", card_number)

    if len(digits_only) != 16:
        return False

    total_sum = 0
    reverse_digits = digits_only[::-1]  # reverse the string — same as your original

    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:          # double every second digit
            n *= 2
            if n > 9:           # if > 9, subtract 9 (same as your original)
                n -= 9
        total_sum += n

    return total_sum % 10 == 0


def find_credit_card(text: str) -> list:
    """
    Find all valid credit card numbers in the given text.
    Accepts formats: 4532015112830366 or 4532-0151-1283-0366 or 4532 0151 1283 0366
    """
    # Regex finds 16-digit patterns with optional dashes/spaces
    pattern = r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"

    matches = []
    for m in re.finditer(pattern, text):
        if _luhn_valid(m.group()):  # only add if Luhn passes
            matches.append(
                Match(value=m.group(), start=m.start(), end=m.end(), pii_type="CREDIT_CARD")
            )
    return matches
