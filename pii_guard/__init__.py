"""pii-guard: keep PII out of LLM prompts, put it back in the answers."""
from pii_guard.guard import GuardResult, PIILeakError, protect
from pii_guard.sanitizer import sanitize
from pii_guard.vault import Vault

__version__ = "1.1.0"
__all__ = ["sanitize", "protect", "Vault", "GuardResult", "PIILeakError"]
