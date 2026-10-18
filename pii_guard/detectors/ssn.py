"""
ssn.py — SSN Detector

YOUR CODE adapted from lesson_05_regex.py.
Change: instead of returning True/False, we return WHERE in the text it was found.

Java equivalent:
    List<Match> matches = new ArrayList<>();
    Matcher m = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b").matcher(text);
    while (m.find()) {
        matches.add(new Match(m.group(), m.start(), m.end(), "SSN"));
    }
    return matches;
"""
import re
from pii_guard.detectors.base import Match


def find_ssn(text: str) -> list:
    """
    Find all SSNs in the given text.
    Returns a list of Match objects — empty list if none found.

    re.finditer() is like Java's while(m.find()) loop — finds ALL matches,
    not just the first one like re.search() does.
    """
    pattern = r"\b\d{3}-\d{2}-\d{4}\b"

    return [
        Match(value=m.group(), start=m.start(), end=m.end(), pii_type="SSN")
        for m in re.finditer(pattern, text)
    ]
