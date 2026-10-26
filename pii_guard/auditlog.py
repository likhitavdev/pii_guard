"""Per-call audit records for protect().

One JSON object per line. A record says what was masked, what the model
received, and what came back, and it never contains an original value:
only token names, masked display strings, lengths and a SHA-256 of the
sanitized prompt.
"""
import hashlib
import json
import os
import re
import uuid
import warnings
from datetime import datetime, timezone

# Anything shaped like one of our tokens, e.g. [SSN_1_0cc49d] or [EMAIL_2].
_TOKEN_LIKE = re.compile(r"\[[A-Z_]+_\d+(?:_[0-9a-f]+)?\]")


def build_record(*, vault, clean_prompt, residual, raw_response, response,
                 outcome, log_prompt=False) -> dict:
    """Build one audit record. ``raw_response``/``response`` may be None."""
    issued = vault.tokens()
    display = vault.all_detections()
    sent_tokens = [t for t in issued if t in clean_prompt]

    sent = {
        "length": len(clean_prompt),
        "sha256": hashlib.sha256(clean_prompt.encode()).hexdigest(),
        "tokens_present": sent_tokens,
        "residual_pii": sorted({m.pii_type for m in residual}),
    }
    if log_prompt:
        sent["prompt"] = clean_prompt

    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "call_id": uuid.uuid4().hex[:12],
        "outcome": outcome,
        "masked": [
            {"token": t, "type": vault.pii_type(t), "display": display[t]}
            for t in sent_tokens
        ],
        "sent": sent,
        "reply": None,
    }

    if raw_response is not None:
        returned = [t for t in sent_tokens if t in raw_response]
        record["reply"] = {
            "length": len(raw_response),
            "tokens_returned": returned,
            "tokens_not_returned": [t for t in sent_tokens if t not in raw_response],
            "unknown_token_like": sorted(
                {t for t in _TOKEN_LIKE.findall(raw_response) if t not in issued}
            ),
            "restored": [t for t in returned if vault.retrieve(t) in response],
        }
    return record


def write_record(path, record) -> None:
    """Append ``record`` to ``path`` as one JSON line. Never raises."""
    try:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        warnings.warn(f"pii-guard: could not write audit log {path!r}: {exc}",
                      RuntimeWarning, stacklevel=3)
