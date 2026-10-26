"""Unit tests for the masking layer: a normal case and an edge case per function."""
from pii_guard.masker import mask_credit_card, mask_email, mask_ssn, mask_phone


# ─── CREDIT CARD MASKING ─────────────────────────────────────────────────────

def test_mask_credit_card_plain_digits():
    """Best case — 16 digits with no formatting."""
    result = mask_credit_card("4532015112830366")
    assert result == "************0366"
    assert "4532015112830" not in result     # no raw digits exposed

def test_mask_credit_card_with_dashes():
    """Detector output can contain separators; they are stripped."""
    result = mask_credit_card("4532-0151-1283-0366")
    assert result.endswith("0366")
    assert "-" not in result                # dashes stripped, digits masked
    assert "*" in result

def test_mask_credit_card_too_short():
    """Worst case — input shorter than 4 digits."""
    result = mask_credit_card("123")
    assert result == "***"                  # all asterisks, no crash


# ─── EMAIL MASKING ───────────────────────────────────────────────────────────

def test_mask_email_standard():
    """Best case — standard username@domain format."""
    result = mask_email("jane@example.com")
    assert result == "j***@example.com"
    assert "jane" not in result             # username masked
    assert "@example.com" in result         # domain preserved

def test_mask_email_long_username():
    """Username with dots — common format like first.last@company.com."""
    result = mask_email("jane.smith@example.com")
    assert result.startswith("j")
    assert result.endswith("@example.com")
    assert "jane" not in result

def test_mask_email_no_at_sign():
    """Worst case — malformed email with no @ symbol."""
    result = mask_email("notanemail")
    assert "*" in result                    # all masked, no crash
    assert "@" not in result


# ─── SSN MASKING ─────────────────────────────────────────────────────────────

def test_mask_ssn_standard_format():
    """Best case — standard XXX-XX-XXXX format."""
    result = mask_ssn("123-45-6789")
    assert result == "***-**-6789"
    assert "123" not in result              # area number masked
    assert "45" not in result               # group number masked
    assert result.endswith("6789")          # last 4 preserved

def test_mask_ssn_last_4_preserved():
    """Different SSN — verifies last 4 are always preserved."""
    result = mask_ssn("987-65-4321")
    assert result.endswith("4321")
    assert "987" not in result

def test_mask_ssn_wrong_format_does_not_crash():
    """Worst case — input without dashes (raw digits)."""
    result = mask_ssn("123456789")
    assert "*" in result                    # some masking applied, no crash
    assert result.endswith("6789")          # last 4 still preserved


# ─── PHONE MASKING ───────────────────────────────────────────────────────────

def test_mask_phone_standard():
    """Best case — US phone with dashes."""
    result = mask_phone("732-555-0101")
    assert result == "***-***-0101"
    assert "732" not in result              # area code masked
    assert "555" not in result              # exchange masked
    assert result.endswith("0101")          # last 4 preserved

def test_mask_phone_with_country_code():
    """Phone with +1 country code prefix."""
    result = mask_phone("+1-732-555-0101")
    assert result.endswith("0101")
    assert "732" not in result

def test_mask_phone_too_short():
    """Worst case — fewer than 4 digits."""
    result = mask_phone("555")
    assert "*" in result                    # all masked, no crash


def test_mask_email_hides_username_length():
    short = mask_email("jo@example.com")
    long_ = mask_email("jonathan.q.public@example.com")
    assert short == long_ == "j***@example.com"


def test_mask_ssn_with_spaces():
    assert mask_ssn("123 45 6789") == "***-**-6789"
