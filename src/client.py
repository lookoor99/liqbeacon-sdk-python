"""HTTP client for the endpoints a consumer needs at runtime.

Standard library only, so the package keeps its zero-dependency promise.
Mirrors ``LiqbeaconClient`` in the Node SDK.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterator, List, Optional, Tuple


class ApiError(Exception):
    """Raised when the API answers with a non-2xx status.

    ``status`` is the HTTP status code (0 when the request never got an
    answer), and ``body`` the raw response text, which usually carries the
    API's ``{"error": ..., "message": ...}``.
    """

    def __init__(self, status: int, reason: str, body: str) -> None:
        super().__init__(f"{status} {reason}: {body}")
        self.status = status
        self.reason = reason
        self.body = body


class LiqbeaconClient:
    """Thin client for the snapshot, replay and cursor endpoints.

    Authenticates with an API key (``sk_live_...``), sent as ``X-Api-Key``.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        if not base_url:
            raise TypeError("LiqbeaconClient: base_url is required")
        if not api_key:
            raise TypeError("LiqbeaconClient: api_key is required")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _request(self, path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"{self._base_url}{path}",
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Api-Key": self._api_key,
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            text = error.read().decode("utf-8", errors="replace")
            raise ApiError(error.code, str(error.reason), text) from error
        except urllib.error.URLError as error:
            raise ApiError(0, "request failed", str(error.reason)) from error
        except OSError as error:
            # A timeout or reset while reading the response is not wrapped in
            # URLError; keep the "status 0 means unreachable" contract anyway.
            reason = "timeout" if isinstance(error, (TimeoutError, socket.timeout)) else "request failed"
            raise ApiError(0, reason, str(error)) from error

    @staticmethod
    def _subscription_path(subscription_id: str, suffix: str) -> str:
        return f"/v1/subscriptions/{urllib.parse.quote(subscription_id, safe='')}/{suffix}"

    def snapshot(
        self,
        subscription_id: str,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """One page of the watched UTxO set.

        Returns ``{"utxos": [...], "next_cursor": str | None, "next_seq": int}``.
        It reflects exactly the events that already have a sequence number:
        apply events from ``next_seq`` onward. When paging, keep the first
        page's ``next_seq`` and apply events idempotently by
        ``(tx_id, index)``.
        """
        params: Dict[str, str] = {}
        if cursor:
            params["after"] = cursor
        if limit:
            params["limit"] = str(limit)
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        return self._request(self._subscription_path(subscription_id, "utxos") + query)

    def load_snapshot(self, subscription_id: str) -> Tuple[List[Dict[str, Any]], int]:
        """Every watched output, following the cursor.

        Returns ``(utxos, next_seq)``, where ``next_seq`` is the first page's
        value -- the one to resume events from. Seed a
        :class:`SequenceTracker` with ``next_seq - 1``.
        """
        utxos: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        next_seq: Optional[int] = None
        while True:
            page = self.snapshot(subscription_id, cursor=cursor, limit=1000)
            if next_seq is None:
                next_seq = page["next_seq"]
            utxos.extend(page["utxos"])
            cursor = page.get("next_cursor")
            if not cursor:
                break
        return utxos, next_seq if next_seq is not None else 1

    def all_utxos(self, subscription_id: str) -> Iterator[Dict[str, Any]]:
        """Iterate every watched output, following the cursor."""
        cursor: Optional[str] = None
        while True:
            page = self.snapshot(subscription_id, cursor=cursor)
            yield from page["utxos"]
            cursor = page.get("next_cursor")
            if not cursor:
                break

    def replay(self, subscription_id: str, from_seq: int, limit: Optional[int] = None) -> Dict[str, Any]:
        """Re-send events from ``from_seq``, with their original ids and seqs.

        The recovery step when :meth:`SequenceTracker.check` reports a gap.
        Returns ``{"requeued": int, "from_seq": int, "message": str}``.
        """
        body: Dict[str, Any] = {"from_seq": from_seq}
        if limit:
            body["limit"] = limit
        return self._request(self._subscription_path(subscription_id, "replay"), method="POST", body=body)

    def cursor(self, subscription_id: str) -> Dict[str, Any]:
        """Sequence range currently retained, for reconciling after an outage.

        Returns ``oldest_retained_seq``, ``latest_seq``,
        ``latest_delivered_seq``, ``next_seq`` and ``replay_window_days``.
        """
        return self._request(self._subscription_path(subscription_id, "events/cursor"))
