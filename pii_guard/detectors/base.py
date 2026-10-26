"""Shared data type returned by every detector."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Match:
    """One PII entity found in a string.

    ``start``/``end`` are character offsets into the scanned text; ``end`` is
    exclusive, so ``text[start:end] == value``.
    """

    value: str
    start: int
    end: int
    pii_type: str  # "SSN", "CREDIT_CARD", "EMAIL" or "PHONE"
