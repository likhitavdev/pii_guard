# pii-guard

Keep PII out of LLM prompts, and put it back in the answers.

`pii-guard` sits between your application and an LLM API. It finds SSNs, payment cards, email addresses and US phone numbers in the outgoing prompt and swaps them for opaque tokens. The model works with the tokens. When the reply comes back, the tokens are swapped for the real values, so the user sees a normal answer. Anything written to logs is a one-way masked version (`***-**-6789`), never the raw value.

```
 user prompt ──► detect ──► tokenize ──► LLM API ──► reply with tokens ──► restore ──► user
                   │            │                                              ▲
                   │            └──► encrypted vault (originals) ──────────────┘
                   └──► masked audit log (safe to store)
```

Two protections, deliberately different:

| | Reversible tokenization | One-way masking |
|---|---|---|
| Purpose | Let the model work on the prompt; restore the answer | Audit logs and monitoring |
| Where it goes | The LLM API | Log storage |
| Example | `[SSN_1_a1b2c3]` | `***-**-6789` |
| Recoverable? | Yes, from the encrypted vault, by the process that holds the key | No |

## Quick start

```bash
pip install -e .
```

```python
from pii_guard import protect

def call_model(prompt: str) -> str:          # any function str -> str
    ...

result = protect("My SSN is 123-45-6789, email jane@example.com", call_model)

result.clean_prompt   # "My SSN is [SSN_1_a1b2c3], email [EMAIL_1_a1b2c3]"  (what the model saw)
result.response       # model reply with tokens replaced by the real values
result.audit          # [{"token": ..., "type": "SSN", "display": "***-**-6789"}, ...]  safe to log
```

Lower-level pieces, if you want to drive the steps yourself:

```python
from pii_guard import sanitize

clean, vault = sanitize("My SSN is 123-45-6789")
vault.restore("Your SSN [SSN_1_...] is on file")   # de-tokenize any text
vault.audit_json()                                  # masked records as JSON
```

`protect()` re-scans the sanitized prompt before sending it and raises `PIILeakError` if a detector still fires, so a bug in tokenization fails closed rather than leaking. Pass the same `Vault` to consecutive calls to keep tokens consistent across a conversation.

Command line:

```bash
python -m pii_guard scan --file input.txt          # tokenized text on stdout, masked audit on stderr
python -m pii_guard scan --file input.txt --json   # {"clean": ..., "audit": [...]}
```

## Audit log: prove what the model saw

Pass `log_path` and `protect()` appends one JSON line per call:

```python
result = protect(prompt, call_model, log_path="pii_guard_audit.jsonl")
```

```json
{"ts": "2026-10-26T15:02:11+00:00", "call_id": "9c1e0b2a7f41", "outcome": "ok",
 "masked": [{"token": "[SSN_1_0cc49d]", "type": "SSN", "display": "***-**-6789"}],
 "sent": {"length": 212, "sha256": "...", "tokens_present": ["[SSN_1_0cc49d]"], "residual_pii": []},
 "reply": {"length": 148, "tokens_returned": [], "tokens_not_returned": ["[SSN_1_0cc49d]"],
           "unknown_token_like": [], "restored": []}}
```

- **`masked`**: what was detected, with masked display values only.
- **`sent`**: which tokens went to the model, and whether any detector still fired on the outgoing text (`residual_pii`). The sanitized prompt itself is logged only with `log_prompt=True`, because it can contain PII the detectors do not cover (names, addresses).
- **`reply`**: which tokens the model returned, which it dropped, which token-shaped strings it invented, and which were restored.
- **`outcome`**: `ok`, `blocked_pii_leak` (the model was never called) or `llm_error`.

Original values are never written. A failure to write the log emits a warning and does not break the call.

## What it detects

| Type | Rule | Example | Masked display |
|---|---|---|---|
| SSN | `AAA-GG-SSSS` with dashes or spaces; area not 000/666/9xx, group not 00, serial not 0000 | `123-45-6789` | `***-**-6789` |
| Credit card | 4-4-4-4, 4-6-5 (Amex) or unbroken 13-19 digits; plausible issuer prefix (Visa, Mastercard, Amex, Discover, Diners, JCB) **and** Luhn checksum | `4532-0151-1283-0366` | `************0366` |
| Email | Structural regex plus dot/domain checks | `jane@example.com` | `j***@example.com` |
| Phone | Formatted US/NANP numbers: separators, `(xxx)` or `+1`; area code and exchange start 2-9 | `(732) 555-0101` | `***-***-0101` |

When detections overlap, card beats SSN beats email beats phone, so a replacement never corrupts the text.

## How the vault works

- Each original is encrypted with **AES-256-GCM**. The token is bound in as associated data, so ciphertexts cannot be swapped between tokens, and tampering raises `InvalidTag`.
- The same value always maps to the same token (`(732) 555-0101` and `732-555-0101` share one). The lookup index is an HMAC, not the plaintext.
- Tokens carry a random per-vault suffix (`[SSN_1_a1b2c3]`). Text that merely *looks* like a token, whether typed by a user or invented by a model, is never restored, because only exact tokens issued by that vault match.
- `repr(vault)` shows only the entry count, and a vault cannot be pickled or deep-copied (it holds key material).
- The key is generated per vault. To control it, pass `Vault(key=<32 bytes>)`, for example from a KMS.

**Scope.** This is an in-process vault. It keeps originals out of logs, tracebacks and accidental serialization. It does not protect against someone who can already read the process's memory, because the key lives there too. For anything that outlives a request, fetch the key from a KMS/HSM and store only ciphertext.

## Measured results

`python -m evaluation.run_eval` scores the detectors against a labeled corpus of 138 cases (positives in several formats and sentence templates, look-alike negatives such as order ids, timestamps, IP addresses and Luhn-failing numbers, and mixed sentences).

| Type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| SSN | 25 | 0 | 0 | 1.000 | 1.000 |
| Credit card | 39 | 0 | 0 | 1.000 | 1.000 |
| Email | 20 | 0 | 0 | 1.000 | 1.000 |
| Phone | 29 | 0 | 0 | 1.000 | 1.000 |

**Read this honestly.** The corpus is synthetic and was written by the author against these exact rules. 1.000 means the rules do what they were designed to do and that CI will catch a regression. It is not an accuracy figure for real-world text. The corpus is the place to add every false positive or miss you find in practice.

## Limitations

Real PII this library does **not** catch (also listed in `evaluation/corpus.py` and checked by a test):

- SSNs and phone numbers written as bare digit runs (`123456789`, `7325550101`). Without separators they are indistinguishable from order and account ids.
- Obfuscated emails (`jane [at] example [dot] com`).
- Non-US phone numbers, and any national id other than the US SSN.
- Names, addresses, dates of birth and anything else that needs context or NER. In the demo prompt, "Jane Smith" goes through untouched.
- A model that paraphrases or reformats a token (`ssn_1`, or dropping the brackets) will not be restored; only exact tokens are.

It is a pattern-and-checksum filter, not a complete DLP product.

## Project structure

```
pii_guard/
├── detectors/        ssn.py, credit_card.py, email.py, phone.py, base.py (Match)
│                     __init__.py: detect_all() with overlap resolution
├── masker.py         one-way display masking
├── vault.py          AES-GCM token vault, restore(), audit log
├── sanitizer.py      detect -> mask -> tokenize -> replace
├── guard.py          protect(): sanitize -> LLM call -> restore, fail-closed check
├── auditlog.py       per-call JSON-lines audit records (masked values only)
├── cli.py            python -m pii_guard scan
evaluation/           labeled corpus + precision/recall runner
tests/                unit, integration, round-trip, CLI and regression tests
example.py            mock or real (gpt-4o-mini) end-to-end demo
```

## Why replace right-to-left?

Tokens are numbered in reading order, but the replacements are applied from the last match to the first. Substituting a token changes the string's length, which would shift the offsets of every later match; working from the right means the offsets still to be processed are never disturbed.

## Develop

```bash
pip install -e ".[dev]"
pytest                          # 91 tests
python -m evaluation.run_eval   # precision/recall on the labeled corpus
```

Demo (`pip install -e ".[example]"` for the real model):

```bash
python example.py                       # mock model
OPENAI_API_KEY=... python example.py    # gpt-4o-mini
```

CI runs the tests on Python 3.10-3.12 plus the evaluation on every push and pull request; a versioned GitHub Release is created when CI passes on `main`.

## Roadmap

- [x] Real LLM integration (OpenAI gpt-4o-mini)
- [x] De-tokenization: restore original values in the LLM response
- [x] Audit log output (JSON)
- [x] Per-call audit file: what was masked, what the model received, what came back
- [x] CLI: `pii-guard scan --file input.txt`
- [x] Encrypted vault (AES-256-GCM) with caller-supplied keys
- [ ] DOB detection
- [ ] National ID formats beyond the US SSN
- [ ] Name/address detection (NER) as an optional extra
- [ ] Streaming responses: restore tokens that arrive split across chunks
