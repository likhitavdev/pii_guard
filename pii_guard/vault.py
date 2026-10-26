"""Token vault: encrypted originals, masked display values.

For every detected value the vault holds

* an **AES-256-GCM ciphertext** of the original (the token is bound in as
  associated data, so ciphertexts cannot be swapped between tokens), and
* a one-way **masked display value** that is safe to write to logs.

Equal values of the same type get the same token. The lookup uses an
HMAC-SHA256 index rather than the plaintext, so the index leaks nothing about
the values either.

Scope of the protection: this is an in-process vault. Encryption keeps
originals out of ``repr()``, tracebacks, accidental serialisation and casual
memory inspection. It does not defend against an attacker who can already read
the process's memory, where the key lives too. For anything longer-lived, pass
a ``key`` fetched from a KMS/HSM and persist nothing but ciphertext.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _canonical(pii_type: str, value: str) -> str:
    """Normalise formatting so ``(732) 555-0101`` and ``732-555-0101`` share a token."""
    if pii_type == "EMAIL":
        return value.lower()
    digits = re.sub(r"\D", "", value)
    if pii_type == "PHONE":
        return digits[-10:]
    return digits


@dataclass(frozen=True)
class _Entry:
    pii_type: str
    display: str
    blob: bytes  # 12-byte GCM nonce || ciphertext+tag


class Vault:
    """Per-request (or per-conversation) store of tokens and protected values.

    Args:
        key: 32-byte master key. A fresh random key is generated if omitted.
        nonce: Suffix mixed into every token, e.g. ``[SSN_1_a1b2c3]``. Because
            the suffix is unguessable, text a user (or a model) writes that
            merely *looks* like a token will not be restored. ``None`` picks a
            random suffix; ``""`` disables it and yields plain ``[SSN_1]``.
    """

    def __init__(self, key: bytes = None, nonce: str = None):
        if key is None:
            key = AESGCM.generate_key(bit_length=256)
        if len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")
        self._enc_key = hmac.new(key, b"pii-guard/enc", hashlib.sha256).digest()
        self._idx_key = hmac.new(key, b"pii-guard/idx", hashlib.sha256).digest()
        self._aead = AESGCM(self._enc_key)
        self._nonce = secrets.token_hex(3) if nonce is None else nonce
        self._entries = {}   # token -> _Entry
        self._index = {}     # HMAC(type, value) -> token
        self._counters = {}  # type -> last number issued

    # -- writing ---------------------------------------------------------

    def store(self, pii_type: str, original_value: str, display_value: str) -> str:
        """Protect ``original_value`` and return its token.

        Storing the same value of the same type again returns the same token.
        """
        idx = hmac.new(
            self._idx_key,
            f"{pii_type}\0{_canonical(pii_type, original_value)}".encode(),
            hashlib.sha256,
        ).hexdigest()
        existing = self._index.get(idx)
        if existing is not None:
            return existing

        number = self._counters.get(pii_type, 0) + 1
        self._counters[pii_type] = number
        suffix = f"_{self._nonce}" if self._nonce else ""
        token = f"[{pii_type}_{number}{suffix}]"

        iv = os.urandom(12)
        blob = iv + self._aead.encrypt(iv, original_value.encode(), token.encode())
        self._entries[token] = _Entry(pii_type, display_value, blob)
        self._index[idx] = token
        return token

    # -- reading ---------------------------------------------------------

    def retrieve(self, token: str) -> str:
        """Decrypt and return the original for ``token``.

        Unknown tokens are returned unchanged, so a caller can never be handed
        a value this vault did not issue.
        """
        entry = self._entries.get(token)
        if entry is None:
            return token
        iv, ciphertext = entry.blob[:12], entry.blob[12:]
        return self._aead.decrypt(iv, ciphertext, token.encode()).decode()

    def retrieve_display(self, token: str) -> str:
        """Masked value for ``token`` (safe to log); unknown tokens pass through."""
        entry = self._entries.get(token)
        return entry.display if entry else token

    def restore(self, text: str) -> str:
        """Replace every token this vault issued with its original value.

        This is the de-tokenization step for an LLM response. Tokens the vault
        did not issue are left as they are, and text is only ever rewritten
        from an exact token match (no fuzzy or case-insensitive matching).
        """
        if not self._entries:
            return text
        pattern = re.compile(
            "|".join(re.escape(t) for t in sorted(self._entries, key=len, reverse=True))
        )
        return pattern.sub(lambda m: self.retrieve(m.group()), text)

    def all_detections(self) -> dict:
        """``{token: masked display value}``. Never contains originals."""
        return {token: e.display for token, e in self._entries.items()}

    def audit_log(self) -> list:
        """Audit records, one per token: ``{"token", "type", "display"}``."""
        return [
            {"token": token, "type": e.pii_type, "display": e.display}
            for token, e in self._entries.items()
        ]

    def audit_json(self) -> str:
        """The audit log as a JSON string, ready for any log pipeline."""
        return json.dumps(self.audit_log())

    def pii_type(self, token: str) -> str:
        """The PII type of ``token``, or ``""`` if this vault did not issue it."""
        entry = self._entries.get(token)
        return entry.pii_type if entry else ""

    def tokens(self) -> list:
        """Every token this vault has issued, in issue order."""
        return list(self._entries)

    def count(self) -> int:
        """Number of distinct protected values."""
        return len(self._entries)

    # -- lifecycle / safety ------------------------------------------------

    def clear(self) -> None:
        """Drop all entries. Without the key the ciphertexts are unreadable."""
        self._entries.clear()
        self._index.clear()
        self._counters.clear()

    def __repr__(self) -> str:
        return f"Vault(entries={len(self._entries)})"

    def __getstate__(self):
        raise TypeError("Vault holds key material and cannot be pickled or copied")
