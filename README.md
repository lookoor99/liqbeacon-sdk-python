# liqbeacon

Verify Liqbeacon webhooks, and notice when you have missed one.

```bash
pip install liqbeacon
```

Python 3.9 or newer. Standard library only, no dependencies.

### Offline install

When PyPI is unreachable, download `liqbeacon-<version>-py3-none-any.whl` from
the console's Quickstart page and install the file:

```bash
pip install --no-index ./liqbeacon-1.0.0-py3-none-any.whl
```

`--no-index` keeps pip from trying the network at all. Install the wheel rather
than the source archive: building from source needs `setuptools`, which an
offline machine may not have. To build the wheel yourself: `pip wheel . --no-deps -w dist`.

## Verify a webhook

```python
import os

from flask import Flask, request
from liqbeacon import verify_event, SignatureError

app = Flask(__name__)

@app.post("/webhooks/cardano")
def webhook():
    try:
        # request.get_data(), not request.json: the signature covers the exact
        # bytes we sent, and a re-serialized body will not match.
        event = verify_event(
            payload=request.get_data(),
            header=request.headers.get("X-Cardano-Signature", ""),
            secret=os.environ["WEBHOOK_SECRET"],
        )
    except SignatureError:
        # Keep the reason server-side; it would tell a forger how close they got.
        return "invalid signature", 400

    handle(event)
    return "", 200
```

`verify_event` raises rather than returning a boolean, so a handler that forgets
to check a return value still fails closed.

While deploying a rotated secret, pass both: `secret=[new_secret, old_secret]`.

## Handle the three event types

```python
if event.is_produced:
    # An output was created at an address you watch.
    credit(event.utxo)

elif event.is_spent:
    # An output you were watching was consumed. The full contents of the spent
    # output are included, so there is nothing to look up.
    debit(event.utxo, event.data["spent_by_tx_id"])

elif event.is_rollback:
    # The chain abandoned a block. Undo the event named here; you have already
    # seen it, and its id is the one you stored.
    revert(event.data["reverted_event_id"])
```

An event rolled back while it was still waiting for `min_confirmations` is
dropped silently: it never took a sequence number, so there is no gap. Once an
event has a sequence number it is always delivered — even if the chain has
abandoned its block by then, in which case it arrives with `rolled_back: true`
and a `rollback` event naming it follows. Make the revert idempotent: it may
name an event you chose to skip because it was already flagged. With
`min_confirmations: 3` or more you will most likely never see one.

## Detect a missed event

`seq` is gap-free per subscription. A jump means an outage lasted long enough to
exhaust retries.

```python
from liqbeacon import LiqbeaconClient, SequenceTracker

client = LiqbeaconClient("https://liqbeacon.com", os.environ["LIQBEACON_API_KEY"])
tracker = SequenceTracker(load_cursors())

duplicate, missing = tracker.check(event)

if duplicate:
    return "", 200          # at-least-once; already handled
if missing:
    first, last = missing   # inclusive range of seqs not yet processed
    log.warning("missed seq %d..%d", first, last)
    client.replay(event.subscription_id, first)

handle(event)               # if this raises, nothing is recorded
tracker.commit(event)       # only after the handler succeeded
```

`missing` is `None` when there is no gap, otherwise `(first, last)`. When
several gaps are open at once, some seqs inside that range may already be
processed; replaying from `first` covers every gap.

`check` never records anything; `commit` does, and only once you call it. That
is what keeps a retried event from being mistaken for a duplicate, and lets
replayed events fill a gap instead of being dropped.

Persist `tracker.snapshot()` alongside your own data so the cursor survives a
restart.

## Load the starting state

Streaming only tells you what changed. To know where you are starting from:

```python
utxos, next_seq = client.load_snapshot("sub_abc123")

# The snapshot reflects exactly the events that already have a sequence
# number. Apply events from next_seq onward; the tracker stores the last
# processed number, so seed it with next_seq - 1.
tracker = SequenceTracker({"sub_abc123": next_seq - 1})

for utxo in client.all_utxos("sub_abc123"):
    ...  # the same outputs, one at a time, if you would rather stream them
```

Apply events idempotently by `(tx_id, index)`: an output sequenced while the
snapshot was being paged may be both in the snapshot and in an event.

## The API client

`LiqbeaconClient(base_url, api_key, timeout=30.0)` authenticates with an API
key (`sk_live_...`) and uses only the standard library.

| Method | Endpoint | Returns |
| --- | --- | --- |
| `snapshot(sub, cursor=None, limit=None)` | `GET /v1/subscriptions/{id}/utxos` | One page: `utxos`, `next_cursor`, `next_seq` |
| `load_snapshot(sub)` | the same, every page | `(utxos, next_seq)`, with the first page's `next_seq` |
| `all_utxos(sub)` | the same, every page | An iterator over the outputs |
| `replay(sub, from_seq, limit=None)` | `POST /v1/subscriptions/{id}/replay` | `requeued`, `from_seq`, `message` |
| `cursor(sub)` | `GET /v1/subscriptions/{id}/events/cursor` | The retained sequence range and `next_seq` |

A non-2xx answer, a 2xx answer that is not JSON, a network failure or a timeout
raises `ApiError`, with `status` (0 when the API could not be reached) and the
raw response `body`.

`verify_event` raises `SignatureError` for a request that cannot be trusted, and
`TypeError` for a configuration mistake: a parsed body (`request.json`) instead
of the raw bytes, or no secret. A correctly signed body that is not a valid
event raises `ValueError`.

## FastAPI

```python
import os

from fastapi import FastAPI, Request, Response
from liqbeacon import verify_event, SignatureError

app = FastAPI()
SECRET = os.environ["WEBHOOK_SECRET"]

@app.post("/webhooks/cardano")
async def webhook(request: Request):
    try:
        event = verify_event(
            payload=await request.body(),
            header=request.headers.get("x-cardano-signature", ""),
            secret=SECRET,
        )
    except SignatureError:
        return Response("invalid signature", status_code=400)

    await handle(event)
    return Response(status_code=200)
```

## Delivery contract

| Property | Behaviour |
| --- | --- |
| Ordering | Strictly by `seq` within a subscription. A failure blocks that queue rather than letting a later event overtake. |
| Duplicates | Possible. Deduplicate on `event.id`, also sent as `Idempotency-Key`. |
| Loss | Retries run for hours. After they are exhausted the subscription pauses and events keep queueing; nothing is discarded. |
| Retries | Exponential with jitter, up to 12 attempts. A non-2xx or a timeout counts as a failure. `410 Gone` stops delivery immediately. |
| Replay | `POST /v1/subscriptions/{id}/replay` re-sends from a sequence number, with the original ids. |
| Rollbacks | Reported explicitly, as a `rollback` event, for anything that already had a sequence number. |
| Secret rotation | For 24 hours after a rotation every delivery carries a `v1` signature from both secrets. Pass both to verify while you deploy. |

Return 2xx quickly. Your response time is inside the delivery timeout, so slow
work belongs on a queue.
