"""Live round trip against the OpenAI API.

Skipped unless OPENAI_API_KEY is set (CI skips it). Run it yourself with:

    pip install -r requirements-example.txt
    pytest tests/test_live_openai.py -v -s

What it proves, and what it deliberately does not:

* Hard assertions cover what pii-guard controls: the model receives tokens and
  no raw PII, nothing still looks like PII on the way out, and the audit log
  holds no original values.
* Whether the model *repeats* the placeholders is the model's choice (it may
  refuse). If it does, restoration is checked on whatever it returned, and a
  warning says it was not exercised. The audit record shows exactly what came back.
"""
import json
import os
import warnings

import pytest

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

openai = pytest.importorskip("openai")

from pii_guard import protect  # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"), reason="OPENAI_API_KEY not set"
)

RAW = ["123-45-6789", "4532-0151-1283-0366", "jane.smith@example.com", "(732) 555-0101"]
PROMPT = (
    "Customer record for support ticket 4821:\n"
    "Name: Jane Smith\n"
    "SSN: 123-45-6789\n"
    "Card on file: 4532-0151-1283-0366\n"
    "Email: jane.smith@example.com\n"
    "Phone: (732) 555-0101\n\n"
    "Write a two-sentence internal note saying we verified this customer's identity.\n"
    "Refer to the SSN, card, email and phone by the exact placeholder text shown in the record.\n"
)


def test_live_round_trip(tmp_path):
    client = openai.OpenAI()
    sent = []

    def call(prompt: str) -> str:
        sent.append(prompt)
        reply = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        return reply.choices[0].message.content

    log = tmp_path / "live_audit.jsonl"
    result = protect(PROMPT, call, log_path=str(log))
    rec = json.loads(log.read_text(encoding="utf-8"))

    # What the model received: one prompt, tokens in, no raw PII.
    assert len(sent) == 1
    for raw in RAW:
        assert raw not in sent[0]
    assert len(rec["sent"]["tokens_present"]) == 4
    assert rec["sent"]["residual_pii"] == []

    # The log itself holds no original values.
    for raw in RAW:
        assert raw not in log.read_text(encoding="utf-8")

    # What came back: whatever tokens the model returned must be restored,
    # and no token this vault issued may reach the user.
    returned = rec["reply"]["tokens_returned"]
    for token in returned:
        assert result.vault.retrieve(token) in result.response
    assert not any(t in result.response for t in result.vault.tokens())

    if not returned:
        warnings.warn(
            "The model returned none of the placeholders, so restoration was not "
            f"exercised. Model said: {result.raw_response[:120]!r}"
        )
