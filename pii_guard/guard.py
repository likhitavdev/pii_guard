"""protect(): the full round trip around an LLM call."""
from dataclasses import dataclass, field

from pii_guard.auditlog import build_record, write_record
from pii_guard.detectors import detect_all
from pii_guard.sanitizer import sanitize
from pii_guard.vault import Vault


class PIILeakError(RuntimeError):
    """The sanitized prompt still contains something that looks like PII."""


@dataclass
class GuardResult:
    response: str          # model reply with tokens restored to originals
    raw_response: str      # model reply exactly as returned (still tokenized)
    clean_prompt: str      # what was actually sent to the model
    vault: Vault
    audit: list = field(default_factory=list)  # masked records, safe to log
    record: dict = None    # this call's audit-log record (masked values only)


def protect(prompt: str, llm_call, *, vault: Vault = None, nonce: str = None,
            strict: bool = True, log_path: str = None,
            log_prompt: bool = False) -> GuardResult:
    """Sanitize ``prompt``, call the model, restore tokens in the reply.

    Args:
        prompt: Raw user text that may contain PII.
        llm_call: ``callable(str) -> str``; receives only the sanitized prompt.
        vault: Optional existing vault for multi-turn conversations.
        nonce: Token suffix for a new vault.
        strict: Re-scan the sanitized prompt before sending and raise
            :class:`PIILeakError` if a detector still fires (fail closed).
        log_path: If set, append one JSON audit record per call to this file.
            Records never contain original values.
        log_prompt: Also store the sanitized prompt in the record. Off by
            default: it can contain PII the detectors do not cover.
    """
    clean, vault = sanitize(prompt, vault=vault, nonce=nonce)
    residual = detect_all(clean)

    def log(outcome, raw=None, response=None):
        record = build_record(
            vault=vault, clean_prompt=clean, residual=residual,
            raw_response=raw, response=response, outcome=outcome,
            log_prompt=log_prompt,
        )
        if log_path:
            write_record(log_path, record)
        return record

    if strict and residual:
        log("blocked_pii_leak")
        raise PIILeakError(
            f"sanitized prompt still contains {sorted({m.pii_type for m in residual})}"
        )

    try:
        raw = llm_call(clean)
    except Exception:
        log("llm_error")
        raise

    response = vault.restore(raw)
    return GuardResult(
        response=response,
        raw_response=raw,
        clean_prompt=clean,
        vault=vault,
        audit=vault.audit_log(),
        record=log("ok", raw, response),
    )
