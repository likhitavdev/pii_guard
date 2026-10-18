"""
vault.py — The Token Vault

THIS is your lesson_06_dictionaries.py concept made useful.

In Java this would be:
    HashMap<String, Map<String, String>> store = new HashMap<>();
    // where each entry holds {"original": rawValue, "display": maskedValue}

    String token = "[SSN_1]";
    store.put(token, Map.of("original", "123-45-6789", "display", "***-**-6789"));
    store.get(token).get("original");  // retrieve for de-tokenization
    store.get(token).get("display");   // retrieve for safe audit logging

The vault does three things:
  1. store(pii_type, original_value, display_value) → generates a token,
     stores BOTH values, returns the token
  2. retrieve(token) → gets the ORIGINAL value back (for de-tokenization)
  3. all_detections() → returns MASKED display values only — safe for audit logs

Why separate original and display?
  - The token replaces the PII in the outgoing prompt (reversible)
  - The masked display goes in the audit log so logs never expose raw PII
"""


class Vault:
    """
    Stores the mapping of token → {original PII value, masked display value}.
    Think of it as a secure HashMap that generates its own keys.
    """

    def __init__(self):
        # Java: HashMap<String, Map<String, String>> store = new HashMap<>();
        # Each value is {"original": "123-45-6789", "display": "***-**-6789"}
        self._store = {}

        # Java: HashMap<String, Integer> counters = new HashMap<>();
        # Tracks how many of each type we've found (so tokens are unique)
        self._counters = {}

    def store(self, pii_type: str, original_value: str, display_value: str) -> str:
        """
        Store the original + display values, return a unique token.

        Example:
            vault.store("SSN", "123-45-6789", "***-**-6789")  →  returns "[SSN_1]"
            vault.store("SSN", "987-65-4321", "***-**-4321")  →  returns "[SSN_2]"
            vault.store("EMAIL", "jane@ex.com", "j***@ex.com") → returns "[EMAIL_1]"

        Args:
            pii_type:      "SSN", "CREDIT_CARD", "EMAIL", or "PHONE"
            original_value: the raw PII text (stored securely for de-tokenization)
            display_value:  masked version for safe audit logging
        """
        # Increment counter for this PII type
        # Java: counters.getOrDefault(piiType, 0) + 1
        count = self._counters.get(pii_type, 0) + 1
        self._counters[pii_type] = count

        # Build the token
        token = f"[{pii_type}_{count}]"

        # Store both values under that token
        # Java: store.put(token, Map.of("original", originalValue, "display", displayValue))
        self._store[token] = {"original": original_value, "display": display_value}

        return token

    def retrieve(self, token: str) -> str:
        """
        Get the ORIGINAL value back by token (for de-tokenization).
        Returns the token itself if not found (safe fallback).

        Java: store.getOrDefault(token, Map.of("original", token)).get("original")
        """
        entry = self._store.get(token)
        return entry["original"] if entry else token

    def retrieve_display(self, token: str) -> str:
        """
        Get the MASKED display value (safe for logging).
        Returns the token itself if not found (safe fallback).
        """
        entry = self._store.get(token)
        return entry["display"] if entry else token

    def all_detections(self) -> dict:
        """
        Return token → masked display value mapping.
        SAFE for audit logs — never exposes raw PII.

        To get original values (for de-tokenization), use retrieve() per token.
        """
        return {token: entry["display"] for token, entry in self._store.items()}

    def count(self) -> int:
        """How many PII entities were found total."""
        return len(self._store)
