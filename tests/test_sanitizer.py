"""
test_sanitizer.py — Integration tests for the full sanitize() pipeline

These tests verify the whole flow:
  input text → detect → tokenize → vault stores mapping → clean text returned

With the masking layer now integrated, we also verify that:
  - vault.retrieve() returns the ORIGINAL value (for de-tokenization)
  - vault.all_detections() returns MASKED display values (safe for audit logs)
"""
from pii_guard.sanitizer import sanitize


def test_ssn_removed_from_text():
    text = "My SSN is 123-45-6789"
    clean, vault = sanitize(text)

    assert "123-45-6789" not in clean        # original gone
    assert "[SSN_1]" in clean                # token present
    assert vault.retrieve("[SSN_1]") == "123-45-6789"   # vault has original


def test_email_removed_from_text():
    text = "Email me at jane@example.com please"
    clean, vault = sanitize(text)

    assert "jane@example.com" not in clean
    assert "[EMAIL_1]" in clean


def test_multiple_pii_types_all_removed():
    """The DSA test — multiple PII types in one string, all must be replaced correctly."""
    text = "SSN: 123-45-6789 and card: 4532015112830366 and email: jane@example.com"
    clean, vault = sanitize(text)

    assert "123-45-6789" not in clean
    assert "4532015112830366" not in clean
    assert "jane@example.com" not in clean
    assert vault.count() == 3


def test_clean_text_unchanged():
    """No PII → text comes back exactly as given."""
    text = "This is a completely clean message with no PII."
    clean, vault = sanitize(text)

    assert clean == text
    assert vault.count() == 0


def test_vault_token_retrieval():
    """Vault returns the original value when given the token."""
    text = "SSN: 123-45-6789"
    clean, vault = sanitize(text)

    token = "[SSN_1]"
    assert vault.retrieve(token) == "123-45-6789"


def test_two_ssns_get_unique_tokens():
    """Two SSNs in the same text should get distinct tokens: [SSN_1] and [SSN_2]."""
    text = "First SSN: 123-45-6789 and second SSN: 987-65-4321"
    clean, vault = sanitize(text)

    assert vault.count() == 2
    assert "123-45-6789" not in clean
    assert "987-65-4321" not in clean


# ─── MASKING LAYER INTEGRATION TESTS ─────────────────────────────────────────
# These verify that all_detections() returns masked values, never raw PII.
# This is the guarantee that makes the audit log safe.

def test_audit_log_shows_masked_ssn():
    """Vault audit log must show masked SSN, not the original."""
    text = "SSN: 123-45-6789"
    clean, vault = sanitize(text)

    detections = vault.all_detections()
    assert detections["[SSN_1]"] == "***-**-6789"       # masked
    assert "123-45-6789" not in str(detections)          # raw NOT in log


def test_audit_log_shows_masked_credit_card():
    """Vault audit log must show masked card number, not full digits."""
    text = "Card: 4532015112830366"
    clean, vault = sanitize(text)

    detections = vault.all_detections()
    masked = detections["[CREDIT_CARD_1]"]
    assert masked.endswith("0366")                       # last 4 preserved
    assert "45320151" not in masked                      # first digits masked


def test_audit_log_shows_masked_email():
    """Vault audit log must show masked email, not full address."""
    text = "Email: jane@example.com"
    clean, vault = sanitize(text)

    detections = vault.all_detections()
    masked = detections["[EMAIL_1]"]
    assert "@example.com" in masked                      # domain preserved
    assert "jane" not in masked                          # username masked


def test_original_still_retrievable_for_detokenization():
    """
    Masking the display does NOT destroy the original.
    Retrieve must still return the raw value for de-tokenization.
    """
    text = "My SSN is 123-45-6789"
    clean, vault = sanitize(text)

    # display (audit log) is masked
    assert vault.all_detections()["[SSN_1]"] == "***-**-6789"

    # original (de-tokenization) is intact
    assert vault.retrieve("[SSN_1]") == "123-45-6789"
