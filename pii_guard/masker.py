"""
masker.py — Display Masking Layer

These functions take a raw PII value and return a safe display version.
Used in the vault audit log so even internal logs never expose raw PII.

The masking logic for credit cards and email came from Hitha's original
masker.py. SSN and phone masking follows the same pattern — keep last 4,
mask everything else.

Masking IS NOT tokenization:
  - Tokenization:  "123-45-6789"  →  "[SSN_1]"     (reversible, goes into prompt)
  - Masking:       "123-45-6789"  →  "***-**-6789"  (display only, for audit logs)

The vault stores BOTH: the token goes into the clean prompt, the masked
display goes into the audit log so even your logs are PII-safe.
"""
import re


def mask_credit_card(card_number: str) -> str:
    """
    Mask all but the last 4 digits of a credit card number.
    Handles formats with dashes or spaces by stripping them first.

    Examples:
        "4532015112830366"     →  "************0366"
        "4532-0151-1283-0366"  →  "************0366"
    """
    digits_only = re.sub(r"\D", "", card_number)
    if len(digits_only) < 4:
        return "*" * len(digits_only)
    return "*" * (len(digits_only) - 4) + digits_only[-4:]


def mask_email(email: str) -> str:
    """
    Mask the username portion of an email address.
    Keeps the first character and the domain visible.

    Examples:
        "jane@example.com"        →  "j***@example.com"
        "jane.smith@example.com"  →  "j***@example.com"
    """
    if "@" not in email:
        return "*" * len(email)
    username, domain = email.split("@", 1)
    if not username:
        return "*" * len(email)
    masked_username = username[0] + "*" * (len(username) - 1)
    return f"{masked_username}@{domain}"


def mask_ssn(ssn: str) -> str:
    """
    Mask all but the last 4 digits of an SSN.
    Preserves the XXX-XX-XXXX format.

    Examples:
        "123-45-6789"  →  "***-**-6789"
    """
    parts = ssn.split("-")
    if len(parts) == 3:
        return f"***-**-{parts[2]}"
    # Fallback: raw digits, keep last 4
    digits = re.sub(r"\D", "", ssn)
    if len(digits) >= 4:
        return "*" * (len(digits) - 4) + digits[-4:]
    return "*" * len(ssn)


def mask_phone(phone: str) -> str:
    """
    Mask all but the last 4 digits of a phone number.
    Returns in a normalized masked format.

    Examples:
        "732-555-0101"    →  "***-***-0101"
        "+1-732-555-0101" →  "***-***-0101"
    """
    digits = re.sub(r"\D", "", phone)
    if len(digits) >= 4:
        return f"***-***-{digits[-4:]}"
    return "*" * len(phone)
