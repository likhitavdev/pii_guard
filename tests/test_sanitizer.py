"""Integration tests for sanitize(): detect -> tokenize -> vault -> clean text."""
from pii_guard import Vault, sanitize


def test_ssn_removed_from_text():
    clean, vault = sanitize("My SSN is 123-45-6789", nonce="")
    assert clean == "My SSN is [SSN_1]"
    assert vault.retrieve("[SSN_1]") == "123-45-6789"


def test_all_four_types_removed():
    text = ("SSN 123-45-6789, card 4532015112830366, email jane@example.com, "
            "phone (732) 555-0101")
    clean, vault = sanitize(text)
    for raw in ("123-45-6789", "4532015112830366", "jane@example.com", "(732) 555-0101"):
        assert raw not in clean
    assert vault.count() == 4
    assert "(" not in clean  # no stray fragment of the phone number is left behind


def test_clean_text_unchanged():
    text = "This is a completely clean message with no PII."
    clean, vault = sanitize(text)
    assert clean == text and vault.count() == 0


def test_tokens_are_numbered_in_reading_order():
    clean, _ = sanitize("First 123-45-6789 then 234-56-7890", nonce="")
    assert clean == "First [SSN_1] then [SSN_2]"


def test_same_value_gets_same_token():
    clean, vault = sanitize("A 123-45-6789 and again 123-45-6789", nonce="")
    assert clean == "A [SSN_1] and again [SSN_1]"
    assert vault.count() == 1


def test_same_phone_in_two_formats_shares_a_token():
    clean, vault = sanitize("(732) 555-0101 or 732-555-0101", nonce="")
    assert clean == "[PHONE_1] or [PHONE_1]"
    assert vault.count() == 1


def test_phone_with_parentheses_fully_replaced():
    clean, _ = sanitize("Call (732) 880-9321 now", nonce="")
    assert clean == "Call [PHONE_1] now"


def test_adjacent_and_mixed_matches_keep_surrounding_text_intact():
    text = "x 4532015112830366,123-45-6789;jane@example.com! y"
    clean, _ = sanitize(text, nonce="")
    assert clean == "x [CREDIT_CARD_1],[SSN_1];[EMAIL_1]! y"


def test_vault_can_be_reused_across_turns():
    _, vault = sanitize("SSN 123-45-6789", nonce="")
    clean, same = sanitize("Remember 123-45-6789 and also 234-56-7890", vault=vault)
    assert same is vault
    assert clean == "Remember [SSN_1] and also [SSN_2]"


# --- audit-log safety --------------------------------------------------------

def test_audit_log_shows_masked_values_only():
    text = "SSN 123-45-6789 card 4532015112830366 email jane@example.com"
    _, vault = sanitize(text, nonce="")
    detections = vault.all_detections()
    assert detections["[SSN_1]"] == "***-**-6789"
    assert detections["[CREDIT_CARD_1]"].endswith("0366")
    assert detections["[EMAIL_1]"] == "j***@example.com"
    blob = str(detections) + vault.audit_json() + repr(vault)
    for raw in ("123-45-6789", "4532015112830366", "jane@example.com", "jane"):
        assert raw not in blob


def test_original_still_retrievable_after_masking():
    _, vault = sanitize("SSN 123-45-6789", nonce="")
    assert vault.all_detections()["[SSN_1]"] == "***-**-6789"
    assert vault.retrieve("[SSN_1]") == "123-45-6789"
