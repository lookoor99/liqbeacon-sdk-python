"""Liqbeacon SDK.

Verify webhooks, detect missed events, and load state or request a replay
through the API.

The two mistakes that break most integrations are verifying against a
re-serialized body (the signature covers the exact bytes that were sent) and
comparing digests with ``==`` (which leaks timing). Everything here takes raw
bytes and uses :func:`hmac.compare_digest`.
"""

# Defined before the submodule imports: client.py reads it for User-Agent.
__version__ = "1.0.0"

from .client import ApiError, LiqbeaconClient
from .events import (
    EVENT_ID_HEADER,
    EVENT_SEQ_HEADER,
    SIGNATURE_HEADER,
    SUBSCRIPTION_HEADER,
    CardanoEvent,
    SequenceTracker,
    SignatureError,
    parse_signature_header,
    verify_event,
)

__all__ = [
    "ApiError",
    "LiqbeaconClient",
    "CardanoEvent",
    "SequenceTracker",
    "SignatureError",
    "parse_signature_header",
    "verify_event",
    "SIGNATURE_HEADER",
    "EVENT_ID_HEADER",
    "EVENT_SEQ_HEADER",
    "SUBSCRIPTION_HEADER",
]
