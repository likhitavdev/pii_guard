# Makes pii_guard/ a Python package.
# Exposes sanitize() at the top level for easy import.
from pii_guard.sanitizer import sanitize

__version__ = "1.0.0"
