"""Unit tests for each detector (best case, worst case, and known edge cases)."""
import pytest

from pii_guard.detectors import detect_all
from pii_guard.detectors.credit_card import find_credit_card, luhn_valid
from pii_guard.detectors.email import find_email
from pii_guard.detectors.phone import find_phone
from pii_guard.detectors.ssn import find_ssn


# --- SSN ---------------------------------------------------------------------

def test_ssn_found_in_sentence():
    matches = find_ssn("My SSN is 123-45-6789 please verify.")
    assert [m.value for m in matches] == ["123-45-6789"]
    assert matches[0].pii_type == "SSN"


def test_ssn_with_spaces():
    assert [m.value for m in find_ssn("SSN 123 45 6789")] == ["123 45 6789"]


def test_ssn_not_found_in_clean_text():
    assert find_ssn("Hello, my name is Jane Smith.") == []


def test_ssn_wrong_format_not_matched():
    assert find_ssn("Not an SSN: 123-4-6789") == []


@pytest.mark.parametrize("bad", ["000-12-3456", "666-12-3456", "900-12-3456",
                                 "123-00-6789", "123-45-0000"])
def test_ssn_invalid_structure_rejected(bad):
    assert find_ssn(f"SSN {bad}") == []


def test_ssn_not_taken_from_inside_a_longer_number():
    assert find_ssn("Serial 1234-56-7890") == []
    assert find_ssn("Date 2024-05-1234") == []


# --- credit card -------------------------------------------------------------

def test_credit_card_luhn_valid():
    matches = find_credit_card("Card: 4532015112830366")
    assert len(matches) == 1 and matches[0].pii_type == "CREDIT_CARD"


def test_credit_card_luhn_invalid_rejected():
    assert find_credit_card("Card: 4532015112830367") == []


@pytest.mark.parametrize("card", [
    "4532-0151-1283-0366", "4532 0151 1283 0366",
    "378282246310005", "3782 822463 10005",          # Amex, 15 digits
    "5555555555554444", "6011111111111117", "30569309025904",
])
def test_credit_card_formats_and_issuers(card):
    assert [m.value for m in find_credit_card(f"pay with {card} now")] == [card]


def test_card_shaped_number_with_unknown_issuer_rejected():
    # Passes Luhn? No - and even a Luhn-valid number needs a known issuer prefix.
    assert find_credit_card("Order 1234567890123456") == []
    assert luhn_valid("0000000000000000") and find_credit_card("0000000000000000") == []


# --- email -------------------------------------------------------------------

def test_email_found():
    matches = find_email("Contact me at jane.smith@example.com for details.")
    assert [m.value for m in matches] == ["jane.smith@example.com"]


def test_email_trailing_period_not_included():
    assert [m.value for m in find_email("Mail jane@example.com.")] == ["jane@example.com"]


def test_email_plus_tag_and_subdomain():
    assert len(find_email("jane+tag@sub.example.co.uk")) == 1


@pytest.mark.parametrize("bad", ["bad-email@", "@example.com", "user@localhost",
                                 "a..b@example.com", "foo@bar..com"])
def test_email_malformed_rejected(bad):
    assert find_email(f"contact {bad} today") == []


# --- phone -------------------------------------------------------------------

@pytest.mark.parametrize("phone", [
    "732-555-0101", "(732) 555-0101", "(732)555-0101", "+1-732-555-0101",
    "+1 732 555 0101", "732.555.0101", "+17325550101",
])
def test_phone_formats(phone):
    # The whole number, including "(" and "+1", must be captured.
    assert [m.value for m in find_phone(f"Call {phone} anytime.")] == [phone]


def test_phone_not_found_in_clean_text():
    assert find_phone("No phone number here.") == []


@pytest.mark.parametrize("text", [
    "Order 2345678901 shipped",     # bare digits: not treated as a phone number
    "Host 192.168.100.200",
    "At 2024-05-12 10:30",
    "Call 732-055-0101",            # exchange cannot start with 0
    "Call 132-555-0101",            # area code cannot start with 1
])
def test_phone_lookalikes_rejected(text):
    assert find_phone(text) == []


# --- overlap resolution ------------------------------------------------------

def test_detect_all_returns_ordered_non_overlapping_matches():
    text = "a@b.co 123-45-6789 4532015112830366 (732) 555-0101"
    matches = detect_all(text)
    assert [m.pii_type for m in matches] == ["EMAIL", "SSN", "CREDIT_CARD", "PHONE"]
    for left, right in zip(matches, matches[1:]):
        assert left.end <= right.start
