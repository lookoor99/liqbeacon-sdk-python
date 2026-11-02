"""Webhook verification and sequence tracking."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union


class SignatureError(Exception):
    """Raised when a webhook cannot be trusted.

    Verification raises rather than returning ``False`` so that a handler which
    forgets to check a result still fails closed.
    """


@dataclass
class CardanoEvent:
    """One delivered event."""

    id: str
    type: str
    subscription_id: str
    created_at: str
    data: Dict[str, Any]
    #: Gap-free per subscription. A jump means an event was missed.
    seq: Optional[int] = None
    block: Optional[Dict[str, Any]] = None
    tx_id: Optional[str] = None
    #: Depth of the block at delivery time.
    confirmations: Optional[int] = None
    #: True when the chain abandoned this block; a rollback event follows.
    rolled_back: bool = False
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "CardanoEvent":
        return cls(
            id=payload["id"],
            type=payload["type"],
            subscription_id=payload["subscription_id"],
            created_at=payload["created_at"],
            data=payload.get("data") or {},
            seq=payload.get("seq"),
            block=payload.get("block"),
            tx_id=payload.get("tx_id"),
            confirmations=payload.get("confirmations"),
            rolled_back=bool(payload.get("rolled_back")),
            raw=payload,
        )

    @property
    def is_produced(self) -> bool:
        return self.type == "utxo.produced"

    @property
    def is_spent(self) -> bool:
        return self.type == "utxo.spent"

    @property
    def is_rollback(self) -> bool:
        return self.type == "rollback"

    @property
    def utxo(self) -> Optional[Dict[str, Any]]:
        """The output this event is about, for produced and spent events."""
        return self.data.get("utxo")


def parse_signature_header(header: str) -> Tuple[int, List[str]]:
    """Split ``t=<ts>,v1=<hex>`` into its timestamp and digests.

    Several ``v1`` values may be present during a secret rotation.
    """
    timestamp = 0
    signatures: List[str] = []

    for part in header.split(","):
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "t":
            # ASCII digits only: the same header must parse the same way in
            # every SDK (int() alone would also take "+17", "1_700" or
            # full-width digits).
            timestamp = int(value) if re.fullmatch(r"[0-9]+", value) else 0
        elif key == "v1" and value:
            signatures.append(value)

    return timestamp, signatures


def verify_event(
    payload: Union[str, bytes, bytearray, memoryview],
    header: str,
    secret: Union[str, Sequence[str]],
    tolerance_seconds: int = 300,
) -> CardanoEvent:
    """Verify a webhook and return the parsed event.

    ``secret`` may be a list: pass both the new and the old secret while
    deploying a rotation, and any one of them may match.

    ``payload`` must be the raw request body. In Flask that is
    ``request.get_data()``, not ``request.json`` -- a re-serialized body has
    different key order and spacing and will never match.

    Raises:
        SignatureError: if the header is missing or malformed, the timestamp is
            outside the tolerance window, or no digest matches.
        TypeError: if ``payload`` is not raw bytes or text, or no secret is
            given -- configuration errors, not forged requests.
    """
    if isinstance(payload, str):
        raw = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray, memoryview)):
        raw = bytes(payload)
    else:
        # Almost always request.json (or a parsed dict) passed by mistake: the
        # raw bytes are gone and no signature can ever match. A TypeError, not
        # a SignatureError, because this is a bug on the receiving side.
        raise TypeError(
            "verify_event: payload must be the raw request body (bytes or str), "
            f"not {type(payload).__name__}. In Flask use request.get_data(); "
            "in FastAPI use await request.body()."
        )

    secrets = [secret] if isinstance(secret, str) else list(secret or [])
    secrets = [s for s in secrets if isinstance(s, str) and s]
    if not secrets:
        raise TypeError("verify_event: no webhook secret configured (is WEBHOOK_SECRET set?)")

    if not header:
        raise SignatureError("missing X-Cardano-Signature header")

    timestamp, signatures = parse_signature_header(header)
    if not timestamp or not signatures:
        raise SignatureError("malformed X-Cardano-Signature header")

    # The timestamp is inside the signed string, so it cannot be moved forward
    # without invalidating the digest. This bounds how long a captured request
    # stays usable.
    age = abs(int(time.time()) - timestamp)
    if age > tolerance_seconds:
        raise SignatureError(
            f"timestamp is {age}s old, outside the {tolerance_seconds}s window"
        )

    signed = f"{timestamp}.".encode("utf-8") + raw
    expected = [
        hmac.new(s.encode("utf-8"), signed, hashlib.sha256).hexdigest().encode("ascii")
        for s in secrets
    ]

    # Compared as bytes: compare_digest raises TypeError on a str holding
    # non-ASCII characters, which would escape the SignatureError contract.
    matched = any(
        hmac.compare_digest(candidate.encode("utf-8"), digest)
        for candidate in signatures
        for digest in expected
    )
    if not matched:
        raise SignatureError("signature mismatch")

    return CardanoEvent.from_dict(json.loads(raw.decode("utf-8")))


class SequenceTracker:
    """Tracks sequence numbers to detect loss and redelivery.

    Use it in two steps around your handler::

        duplicate, missing = tracker.check(event)
        if duplicate:
            return "", 200          # already processed
        if missing:
            request_replay(missing[0])
        handle(event)               # may raise: nothing is recorded
        tracker.commit(event)       # only after it really succeeded

    Committing only after success is what makes a retry of a failed event a
    retry, not a "duplicate". And because committed numbers above a gap are
    remembered individually, events replayed to fill a gap are recognised as
    new.

    Seed it from a snapshot with ``next_seq - 1``: the tracker stores the last
    sequence number processed, not the next one expected.
    """

    def __init__(self, initial: Optional[Dict[str, int]] = None) -> None:
        #: Highest seq such that it and everything below it are committed.
        self._contiguous: Dict[str, int] = dict(initial or {})
        #: Committed seqs above the contiguous mark, beyond a gap.
        self._above: Dict[str, Set[int]] = {}

    def check(self, event: CardanoEvent) -> Tuple[bool, List[int]]:
        """Classify an event without recording it.

        Returns:
            ``(duplicate, missing)`` -- whether this event was already
            processed, and the sequence numbers before it not yet committed.
        """
        if event.seq is None:
            return False, []

        mark = self._contiguous.get(event.subscription_id)
        # Nothing known yet: this event sets the baseline.
        if mark is None:
            return False, []

        above = self._above.get(event.subscription_id, set())
        if event.seq <= mark or event.seq in above:
            return True, []

        missing = [seq for seq in range(mark + 1, event.seq) if seq not in above]
        return False, missing

    def commit(self, event: CardanoEvent) -> None:
        """Record an event as processed. Call only once your handler succeeded."""
        if event.seq is None:
            return
        sub = event.subscription_id

        mark = self._contiguous.get(sub)
        if mark is None:
            self._contiguous[sub] = event.seq
            return
        if event.seq <= mark:
            return

        above = self._above.setdefault(sub, set())
        above.add(event.seq)
        while mark + 1 in above:
            mark += 1
            above.discard(mark)
        self._contiguous[sub] = mark
        if not above:
            del self._above[sub]

    def track(self, event: CardanoEvent) -> Tuple[bool, List[int]]:
        """``check`` and ``commit`` in one call.

        Only safe when handling cannot fail after this point; otherwise use
        the two-step form.
        """
        duplicate, missing = self.check(event)
        if not duplicate:
            self.commit(event)
        return duplicate, missing

    def cursor(self, subscription_id: str) -> Optional[int]:
        """Last sequence number up to which everything has been processed."""
        return self._contiguous.get(subscription_id)

    def snapshot(self) -> Dict[str, int]:
        """Persist this alongside your own data so the cursor survives a restart.

        Only the contiguous mark is kept; anything committed beyond a gap is
        redelivered by the replay that fills it, and deduplicated on the id.
        """
        return dict(self._contiguous)
