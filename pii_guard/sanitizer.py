"""sanitize(): detect PII in text and swap it for vault tokens."""
from pii_guard.detectors import detect_all
from pii_guard.masker import MASKERS
from pii_guard.vault import Vault


def sanitize(text: str, *, vault: Vault = None, nonce: str = None) -> tuple:
    """Replace PII in ``text`` with tokens. Returns ``(clean_text, vault)``.

    Args:
        text: Raw text, e.g. a user prompt.
        vault: Reuse an existing vault so tokens stay consistent across the
            turns of one conversation. A new vault is created if omitted.
        nonce: Token suffix for a new vault (see :class:`Vault`). Ignored when
            ``vault`` is given.

    Tokens are numbered in reading order. Replacements are applied from the
    right so that substituting one match never shifts the offsets of the
    matches still to be processed.
    """
    if vault is None:
        vault = Vault(nonce=nonce)

    matches = detect_all(text)  # ascending by position, non-overlapping
    tokens = [
        vault.store(m.pii_type, m.value, MASKERS[m.pii_type](m.value)) for m in matches
    ]
    for match, token in reversed(list(zip(matches, tokens))):
        text = text[: match.start] + token + text[match.end :]
    return text, vault
