"""End-to-end: protect() around a fake model."""
import json

import pytest

from pii_guard import PIILeakError, Vault, protect
from pii_guard.detectors import detect_all

PROMPT = ("Please review: SSN 123-45-6789, card 4532015112830366, "
          "email jane@example.com, phone (732) 555-0101.")
RAW = ("123-45-6789", "4532015112830366", "jane@example.com", "(732) 555-0101")


def test_model_never_sees_raw_pii_and_reply_is_restored():
    seen = []

    def fake_llm(prompt):
        seen.append(prompt)
        tokens = [w.strip(",.") for w in prompt.split() if w.startswith("[")]
        return "Confirmed: " + " / ".join(tokens)

    result = protect(PROMPT, fake_llm)

    assert len(seen) == 1
    for raw in RAW:
        assert raw not in seen[0]            # request side
        assert raw in result.response        # response side: de-tokenized
        assert raw not in result.raw_response
    assert result.clean_prompt == seen[0]


def test_audit_trail_is_json_serialisable_and_masked():
    result = protect(PROMPT, lambda p: p)
    blob = json.dumps(result.audit)
    assert len(result.audit) == 4
    for raw in RAW:
        assert raw not in blob
    assert {r["type"] for r in result.audit} == {"SSN", "CREDIT_CARD", "EMAIL", "PHONE"}


def test_tokens_the_model_invents_are_left_alone():
    result = protect("SSN 123-45-6789", lambda p: "Also see [SSN_7_ffffff] and [EMAIL_1_000000]")
    assert result.response == "Also see [SSN_7_ffffff] and [EMAIL_1_000000]"


def test_multi_turn_conversation_shares_one_vault():
    vault = Vault(nonce="")
    first = protect("My SSN is 123-45-6789", lambda p: "ok", vault=vault)
    second = protect("Is 123-45-6789 on file?", lambda p: f"Checking {p}", vault=vault)
    assert first.vault is second.vault
    assert second.clean_prompt == "Is [SSN_1] on file?"
    assert second.response == "Checking Is 123-45-6789 on file?"


def test_strict_mode_fails_closed(monkeypatch):
    # Simulate a gap in sanitize(): make it return the text untouched.
    import pii_guard.guard as guard

    monkeypatch.setattr(guard, "sanitize", lambda text, **kw: (text, Vault()))
    called = []
    with pytest.raises(PIILeakError):
        protect("SSN 123-45-6789", lambda p: called.append(p) or "x")
    assert called == []  # the model was never called


def test_sanitized_prompt_rescans_clean():
    result = protect(PROMPT, lambda p: p)
    assert detect_all(result.clean_prompt) == []
