"""
sanitizer.py — The Orchestrator

This is the main engine. It:
  1. Runs all detectors on the input text
  2. Sorts matches by position DESCENDING (the DSA insight — explained below)
  3. For each match, generates a masked display value via the masking layer
  4. Replaces each match with a token
  5. Returns the clean text + the vault

The DSA insight:
  If text = "SSN: 123-45-6789 and card: 4532015112830366"
  SSN is at index 5, card is at index 27.

  If you replace SSN first → "SSN: [SSN_1] and card: 4532015112830366"
  Now the card's index has SHIFTED because "[SSN_1]" is a different length than "123-45-6789".

  Solution: sort by start position DESCENDING → replace from RIGHT to LEFT.
  Replacing something on the right doesn't change the indices of anything to its left.

  Java equivalent:
    matches.sort(Comparator.comparingInt(Match::getStart).reversed());
    for (Match m : matches) {
        StringBuilder sb = new StringBuilder(text);
        sb.replace(m.getStart(), m.getEnd(), token);
        text = sb.toString();
    }

The masking layer:
  For each match, we call the appropriate mask_*() function to generate a
  display-safe version (e.g., "***-**-6789" for an SSN).
  The vault stores BOTH the original (for de-tokenization) and the display
  (for audit logs). The clean prompt only ever sees the token.
"""
from pii_guard.detectors.ssn import find_ssn
from pii_guard.detectors.credit_card import find_credit_card
from pii_guard.detectors.email import find_email
from pii_guard.detectors.phone import find_phone
from pii_guard.masker import mask_ssn, mask_credit_card, mask_email, mask_phone
from pii_guard.vault import Vault


# Maps each PII type to its masking function
# Java equivalent: Map<String, Function<String, String>> MASKERS = new HashMap<>();
PII_MASKERS = {
    "SSN": mask_ssn,
    "CREDIT_CARD": mask_credit_card,
    "EMAIL": mask_email,
    "PHONE": mask_phone,
}


def sanitize(text: str) -> tuple:
    """
    Scan text for PII, replace each with a token, return (clean_text, vault).

    The vault stores both the original value (for de-tokenization) and the
    masked display value (for safe audit logging).

    Usage:
        clean, vault = sanitize("My SSN is 123-45-6789")
        # clean  = "My SSN is [SSN_1]"
        # vault.retrieve("[SSN_1]")     = "123-45-6789"  (original, for de-tokenization)
        # vault.all_detections()        = {"[SSN_1]": "***-**-6789"}  (masked, safe to log)
    """
    vault = Vault()

    # --- Step 1: Run all detectors, collect every match ---
    all_matches = []
    all_matches.extend(find_ssn(text))
    all_matches.extend(find_credit_card(text))
    all_matches.extend(find_email(text))
    all_matches.extend(find_phone(text))

    # --- Step 2: Sort by start position DESCENDING (right to left) ---
    # Java: matches.sort(Comparator.comparingInt(Match::getStart).reversed())
    # Python lambda: m.start is the field we sort on, reverse=True means descending
    all_matches.sort(key=lambda m: m.start, reverse=True)

    # --- Step 3: Replace each match with a token ---
    for match in all_matches:
        # Get the masking function for this PII type
        masker_fn = PII_MASKERS[match.pii_type]
        display_value = masker_fn(match.value)

        # Store both original and display in the vault, get back the token
        token = vault.store(match.pii_type, match.value, display_value)

        # Replace in the text — right-to-left so indices stay valid
        # Java: text = text.substring(0, m.start) + token + text.substring(m.end)
        text = text[:match.start] + token + text[match.end:]

    return text, vault
