"""
base.py — The Match data class

Java equivalent of a simple POJO / Record:
    public record Match(String value, int start, int end, String piiType) {}

In Python, @dataclass does the same thing — generates __init__, __repr__ automatically.
"""
from dataclasses import dataclass


@dataclass
class Match:
    """Represents one PII entity found in a text string."""
    value: str      # the actual PII text found, e.g. "123-45-6789"
    start: int      # index where it starts in the original string
    end: int        # index where it ends (exclusive, like Java's Matcher.end())
    pii_type: str   # e.g. "SSN", "CREDIT_CARD", "EMAIL", "PHONE"
