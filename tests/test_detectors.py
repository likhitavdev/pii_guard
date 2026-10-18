"""
test_detectors.py — Unit tests for each PII detector

Run with:  pytest tests/ -v

Each test:
  - Gives the detector a string
  - Asserts it found the right thing (or correctly found nothing)
"""
import pytest
from pii_guard.detectors.ssn import find_ssn
from pii_guard.detectors.credit_card import find_credit_card
from pii_guard.detectors.email import find_email
from pii_guard.detectors.phone import find_phone


# ─── SSN TESTS ────────────────────────────────────────────────────────────────

def test_ssn_found_in_sentence():
    matches = find_ssn("My SSN is 123-45-6789 please verify.")
    assert len(matches) == 1
    assert matches[0].value == "123-45-6789"
    assert matches[0].pii_type == "SSN"

def test_ssn_not_found_in_clean_text():
    matches = find_ssn("Hello, my name is Jane Smith.")
    assert len(matches) == 0

def test_ssn_wrong_format_not_matched():
    # Only 2 digits in middle group — not a valid SSN format
    matches = find_ssn("Not an SSN: 123-4-6789")
    assert len(matches) == 0


# ─── CREDIT CARD TESTS ────────────────────────────────────────────────────────

def test_credit_card_luhn_valid():
    # This is a real Luhn-valid test number (Visa test card)
    matches = find_credit_card("Card: 4532015112830366")
    assert len(matches) == 1
    assert matches[0].pii_type == "CREDIT_CARD"

def test_credit_card_luhn_invalid_rejected():
    # Same digits, last one changed — Luhn will fail
    matches = find_credit_card("Card: 4532015112830367")
    assert len(matches) == 0

def test_credit_card_with_dashes():
    matches = find_credit_card("Card: 4532-0151-1283-0366")
    assert len(matches) == 1


# ─── EMAIL TESTS ──────────────────────────────────────────────────────────────

def test_email_found():
    matches = find_email("Contact me at jane.smith@example.com for details.")
    assert len(matches) == 1
    assert matches[0].value == "jane.smith@example.com"

def test_email_not_found_in_clean_text():
    matches = find_email("No email address here.")
    assert len(matches) == 0

def test_email_without_domain_rejected():
    matches = find_email("bad-email@")
    assert len(matches) == 0


# ─── PHONE TESTS ──────────────────────────────────────────────────────────────

def test_phone_found_with_dashes():
    matches = find_phone("Call me at 732-555-0101 anytime.")
    assert len(matches) == 1
    assert matches[0].pii_type == "PHONE"

def test_phone_found_with_country_code():
    matches = find_phone("Reach me at +1-732-555-0101")
    assert len(matches) == 1

def test_phone_not_found_in_clean_text():
    matches = find_phone("No phone number here.")
    assert len(matches) == 0
