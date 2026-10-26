"""The audit log: what was masked, what the model got, what came back."""
import json

import pytest

from pii_guard import PIILeakError, Vault, protect

PROMPT = ("Please review: SSN 123-45-6789, card 4532015112830366, "
          "email jane@example.com, phone (732) 555-0101.")
RAW = ("123-45-6789", "4532015112830366", "jane@example.com", "(732) 555-0101")


def echo(prompt):
    return "Got: " + " ".join(w.strip(",.") for w in prompt.split() if w.startswith("["))


def lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("log_prompt", [False, True])
def test_log_never_contains_original_values(tmp_path, log_prompt):
    log = tmp_path / "run_audit.jsonl"
    protect(PROMPT, echo, log_path=str(log), log_prompt=log_prompt)
    text = log.read_text(encoding="utf-8")
    for raw in RAW:
        assert raw not in text


def test_echoing_model_shows_tokens_sent_returned_and_restored(tmp_path):
    log = tmp_path / "a.jsonl"
    result = protect(PROMPT, echo, log_path=str(log))
    rec = lines(log)[0]
    issued = result.vault.tokens()

    assert rec["outcome"] == "ok"
    assert {m["type"] for m in rec["masked"]} == {"SSN", "CREDIT_CARD", "EMAIL", "PHONE"}
    assert rec["sent"]["tokens_present"] == issued
    assert rec["sent"]["residual_pii"] == []
    assert rec["reply"]["tokens_returned"] == issued
    assert rec["reply"]["tokens_not_returned"] == []
    assert rec["reply"]["restored"] == issued
    assert rec == result.record


def test_refusing_model_is_visible_in_the_log(tmp_path):
    """The case from the live run: tokens went out, the model refused, none came back."""
    log = tmp_path / "a.jsonl"
    result = protect(PROMPT, lambda p: "I'm sorry, I can't help with that.", log_path=str(log))
    rec = lines(log)[0]
    assert rec["sent"]["tokens_present"] == result.vault.tokens()
    assert rec["reply"]["tokens_returned"] == []
    assert rec["reply"]["tokens_not_returned"] == result.vault.tokens()
    assert rec["reply"]["restored"] == []


def test_invented_and_altered_tokens_are_flagged(tmp_path):
    log = tmp_path / "a.jsonl"
    result = protect("SSN 123-45-6789", lambda p: "Your SSN is [SSN_7_ffffff]", log_path=str(log))
    rec = lines(log)[0]
    assert rec["reply"]["unknown_token_like"] == ["[SSN_7_ffffff]"]
    assert rec["reply"]["tokens_returned"] == []
    assert "[SSN_7_ffffff]" in result.response  # unknown tokens are never restored


def test_prompt_is_logged_only_when_asked(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    protect(PROMPT, echo, log_path=str(a))
    protect(PROMPT, echo, log_path=str(b), log_prompt=True)
    assert "prompt" not in lines(a)[0]["sent"]
    assert lines(b)[0]["sent"]["prompt"].startswith("Please review: SSN [SSN_1_")


def test_blocked_call_is_logged_and_model_never_called(tmp_path, monkeypatch):
    import pii_guard.guard as guard

    monkeypatch.setattr(guard, "sanitize", lambda text, **kw: (text, Vault()))
    log = tmp_path / "a.jsonl"
    called = []
    with pytest.raises(PIILeakError):
        protect("SSN 123-45-6789", lambda p: called.append(p) or "x", log_path=str(log))
    rec = lines(log)[0]
    assert called == []
    assert rec["outcome"] == "blocked_pii_leak"
    assert rec["sent"]["residual_pii"] == ["SSN"]
    assert rec["reply"] is None
    assert "123-45-6789" not in log.read_text(encoding="utf-8")


def test_llm_error_is_logged_and_reraised(tmp_path):
    def boom(prompt):
        raise RuntimeError("api down")

    log = tmp_path / "a.jsonl"
    with pytest.raises(RuntimeError, match="api down"):
        protect(PROMPT, boom, log_path=str(log))
    rec = lines(log)[0]
    assert rec["outcome"] == "llm_error"
    assert rec["reply"] is None


def test_one_line_per_call_and_parent_dirs_are_created(tmp_path):
    log = tmp_path / "logs" / "nested" / "a.jsonl"
    vault = Vault()
    protect(PROMPT, echo, vault=vault, log_path=str(log))
    protect("Again: SSN 123-45-6789", echo, vault=vault, log_path=str(log))
    recs = lines(log)
    assert len(recs) == 2
    assert recs[0]["call_id"] != recs[1]["call_id"]


def test_unwritable_log_warns_but_does_not_break_the_call(tmp_path):
    with pytest.warns(RuntimeWarning, match="could not write audit log"):
        result = protect(PROMPT, echo, log_path=str(tmp_path))  # a directory, not a file
    assert "123-45-6789" in result.response


def test_no_log_path_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = protect(PROMPT, echo)
    assert list(tmp_path.iterdir()) == []
    assert result.record["outcome"] == "ok"
