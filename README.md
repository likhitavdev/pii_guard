# pii-guard

A Python library that intercepts user prompts **before they reach an LLM API**, scans for PII/PHI, replaces sensitive data with reversible tokens, and stores the original values in a secure vault. Even audit logs are safe — the vault exposes only masked display values, never raw PII.

Built to demonstrate input-layer data protection — the same principle applied at enterprise scale in production data security infrastructure.

---

## How it works

```
user prompt
     │
     ▼
┌─────────────────────┐
│   PII Detectors     │  ◄── SSN, Credit Card (Luhn), Email, Phone
│   (regex + rules)   │
└─────────┬───────────┘
          │  list of Match(value, start, end, type)
          ▼
┌─────────────────────┐
│   Masking Layer     │  ◄── mask_ssn(), mask_credit_card(), mask_email(), mask_phone()
│   (display safety)  │
└─────────┬───────────┘
          │  (original, masked_display)
          ▼
┌─────────────────────┐
│   Sanitizer         │  ◄── sorts by position (right→left), replaces with tokens
└─────────┬───────────┘
          │
     ┌────┴────────────────────────────────┐
     │                                      │
     ▼                                      ▼
clean prompt                          Vault (dict)
"My SSN is [SSN_1]"      token → {original: "123-45-6789",
     │                              display:  "***-**-6789"}
     ▼
  LLM API  ◄── PII never reaches the model
```

---

## Quick start

```python
from pii_guard import sanitize

prompt = "My SSN is 123-45-6789 and my card is 4532-0151-1283-0366"

clean_prompt, vault = sanitize(prompt)

print(clean_prompt)
# → "My SSN is [SSN_1] and my card is [CREDIT_CARD_1]"

# Audit log — safe to write to any log system
print(vault.all_detections())
# → {"[SSN_1]": "***-**-6789", "[CREDIT_CARD_1]": "************0366"}

# De-tokenization — retrieve original when needed
print(vault.retrieve("[SSN_1]"))
# → "123-45-6789"
```

---

## PII types detected and masked

| Type | Detection | Example input | Masked display |
|---|---|---|---|
| SSN | Regex `\b\d{3}-\d{2}-\d{4}\b` | `123-45-6789` | `***-**-6789` |
| Credit Card | Regex + Luhn algorithm | `4532-0151-1283-0366` | `************0366` |
| Email | Regex + structural validation | `jane@example.com` | `j***@example.com` |
| Phone | US regex with +1 support | `+1-732-555-0101` | `***-***-0101` |

---

## Project structure

```
pii-guard/
├── pii_guard/
│   ├── detectors/
│   │   ├── base.py          # Match data class
│   │   ├── credit_card.py   # Luhn-validated card detection
│   │   ├── email.py         # Email detection + validation
│   │   ├── phone.py         # US phone detection
│   │   └── ssn.py           # SSN detection
│   ├── masker.py            # Display masking (safe values for audit logs)
│   ├── vault.py             # Token → {original, display} store (HashMap)
│   └── sanitizer.py        # Orchestrates detect → mask → tokenize → store
├── tests/
│   ├── test_detectors.py    # Unit tests per detector (best + worst case)
│   ├── test_masker.py       # Unit tests per masking function (best + worst case)
│   └── test_sanitizer.py   # Integration tests: pipeline + audit log safety
├── .github/workflows/
│   └── ci.yml              # CI: pytest on every push/PR; CD: GitHub Release on main
├── example.py              # Full demo with mock LLM call
└── requirements.txt
```

---

## Run the tests

```bash
pip install pytest
pytest tests/ -v
```

Expected: **34 tests, all passing.**

---

## Run the demo

```bash
python example.py
```

---

## Why right-to-left replacement?

When multiple PII entities exist in one string, replacing the leftmost one first shifts all subsequent indices — the string is now a different length. Sorting matches by position **descending** and replacing right-to-left means each replacement never affects the indices of anything to its left. This is the same approach used in compiler/parser implementations for AST node replacement.

---

## Why two values in the vault?

The vault stores both the **original value** and a **masked display value** for each token:

- The **token** (`[SSN_1]`) replaces the PII in the outgoing prompt — reversible via `vault.retrieve()`
- The **masked display** (`***-**-6789`) is what appears in audit logs via `vault.all_detections()`

This means even if your logging infrastructure is compromised, raw PII is never exposed in logs.

---

## CI/CD pipeline

Every push triggers two jobs:

1. **CI (test):** Runs `pytest tests/ -v` on Python 3.11. All 30 tests must pass.
2. **CD (release):** If tests pass **and** the push is to `main`, a versioned GitHub Release is created automatically (`v1.0.N` where N is the build number).

Pull requests only trigger the CI job — no release is created until code merges to `main`.

---

## Roadmap

## Roadmap

- [ ] DOB detection
- [ ] National ID support (international formats)
- [x] Real LLM API integration (OpenAI gpt-4o-mini) — tested and working
- [ ] De-tokenization: restore original values in LLM response
- [ ] Audit log output (JSON)
- [ ] CLI interface: `pii-guard scan --file input.txt`