"""Vault: encryption, token integrity, restore()."""
import copy
import pickle

import pytest

from pii_guard import Vault, sanitize


def test_originals_are_encrypted_in_memory():
    vault = Vault(nonce="")
    vault.store("SSN", "123-45-6789", "***-**-6789")
    entry = vault._entries["[SSN_1]"]
    assert b"123-45-6789" not in entry.blob
    assert "123-45-6789" not in repr(vault._entries) .replace("***-**-6789", "")
    assert vault.retrieve("[SSN_1]") == "123-45-6789"


def test_same_value_reuses_token_and_distinct_values_do_not():
    vault = Vault(nonce="")
    a = vault.store("SSN", "123-45-6789", "x")
    b = vault.store("SSN", "123-45-6789", "x")
    c = vault.store("SSN", "234-56-7890", "x")
    assert a == b == "[SSN_1]" and c == "[SSN_2]"


def test_unknown_token_is_returned_unchanged():
    vault = Vault(nonce="")
    assert vault.retrieve("[SSN_9]") == "[SSN_9]"
    assert vault.retrieve_display("[SSN_9]") == "[SSN_9]"


def test_tampered_ciphertext_is_rejected():
    from cryptography.exceptions import InvalidTag

    vault = Vault(nonce="")
    vault.store("SSN", "123-45-6789", "d")
    entry = vault._entries["[SSN_1]"]
    flipped = bytearray(entry.blob)
    flipped[-1] ^= 1
    vault._entries["[SSN_1]"] = type(entry)(entry.pii_type, entry.display, bytes(flipped))
    with pytest.raises(InvalidTag):
        vault.retrieve("[SSN_1]")


def test_ciphertext_is_bound_to_its_token():
    from cryptography.exceptions import InvalidTag

    vault = Vault(nonce="")
    vault.store("SSN", "123-45-6789", "d")
    vault.store("SSN", "234-56-7890", "d")
    vault._entries["[SSN_1]"], vault._entries["[SSN_2]"] = (
        vault._entries["[SSN_2]"], vault._entries["[SSN_1]"])
    with pytest.raises(InvalidTag):
        vault.retrieve("[SSN_1]")


def test_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        Vault(key=b"short")


def test_supplied_key_is_used():
    key = bytes(range(32))
    a, b = Vault(key=key, nonce=""), Vault(key=key, nonce="")
    a.store("SSN", "123-45-6789", "d")
    b.store("SSN", "123-45-6789", "d")
    assert a._index == b._index  # deterministic index under one key


def test_vault_cannot_be_pickled_or_copied():
    vault = Vault()
    with pytest.raises(TypeError):
        pickle.dumps(vault)
    with pytest.raises(TypeError):
        copy.deepcopy(vault)


def test_clear_removes_everything():
    _, vault = sanitize("SSN 123-45-6789", nonce="")
    vault.clear()
    assert vault.count() == 0 and vault.restore("[SSN_1]") == "[SSN_1]"


# --- nonce -------------------------------------------------------------------

def test_default_tokens_carry_a_random_suffix():
    clean1, v1 = sanitize("SSN 123-45-6789")
    clean2, v2 = sanitize("SSN 123-45-6789")
    assert clean1 != clean2
    assert v1.restore(clean1).endswith("123-45-6789")


def test_text_that_only_looks_like_a_token_is_not_restored():
    clean, vault = sanitize("SSN 123-45-6789")
    forged = "[SSN_1]"  # what an attacker would guess without the suffix
    assert vault.restore(forged) == forged


# --- restore -----------------------------------------------------------------

def test_restore_replaces_every_occurrence():
    clean, vault = sanitize("SSN 123-45-6789", nonce="")
    assert vault.restore("[SSN_1] ... again [SSN_1]") == "123-45-6789 ... again 123-45-6789"


def test_restore_handles_ten_or_more_tokens():
    text = " ".join(f"{100 + i}-45-6789" for i in range(12))
    clean, vault = sanitize(text, nonce="")
    assert "[SSN_12]" in clean
    assert vault.restore(clean) == text


def test_restore_is_exact_match_only():
    _, vault = sanitize("SSN 123-45-6789", nonce="")
    assert vault.restore("[ssn_1]") == "[ssn_1]"
    assert vault.restore("SSN_1") == "SSN_1"
