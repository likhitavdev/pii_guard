"""Display masking for audit logs.

Masking is one-way: the output cannot be turned back into the original. It is
what ``Vault.audit_log()`` records, so logs never contain raw PII.

Tokenization (``123-45-6789`` -> ``[SSN_1_a1b2c3]``) is the reversible
operation and lives in :mod:`pii_guard.vault`.
"""
import re


def mask_credit_card(card_number: str) -> str:
    """Keep the last four digits: ``4532-0151-1283-0366`` -> ``************0366``."""
    digits = re.sub(r"\D", "", card_number)
    if len(digits) < 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_email(email: str) -> str:
    """Keep the first character and the domain: ``jane.smith@x.com`` -> ``j***@x.com``.

    The number of asterisks is fixed so the mask does not reveal the length of
    the local part.
    """
    if "@" not in email:
        return "*" * len(email)
    username, domain = email.split("@", 1)
    if not username:
        return "*" * len(email)
    return f"{username[0]}***@{domain}"


def mask_ssn(ssn: str) -> str:
    """Keep the last four digits: ``123-45-6789`` -> ``***-**-6789``."""
    digits = re.sub(r"\D", "", ssn)
    if len(digits) == 9:
        return f"***-**-{digits[-4:]}"
    if len(digits) >= 4:
        return "*" * (len(digits) - 4) + digits[-4:]
    return "*" * len(ssn)


def mask_phone(phone: str) -> str:
    """Keep the last four digits: ``+1-732-555-0101`` -> ``***-***-0101``."""
    digits = re.sub(r"\D", "", phone)
    if len(digits) >= 4:
        return f"***-***-{digits[-4:]}"
    return "*" * len(phone)


MASKERS = {
    "SSN": mask_ssn,
    "CREDIT_CARD": mask_credit_card,
    "EMAIL": mask_email,
    "PHONE": mask_phone,
}
