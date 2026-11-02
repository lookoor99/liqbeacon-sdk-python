"""Run with: python -m unittest discover -s tests"""

import hashlib
import hmac
import json
import time
import unittest
from unittest import mock

from liqbeacon import ApiError, LiqbeaconClient, SequenceTracker, SignatureError, verify_event
from liqbeacon.events import CardanoEvent, parse_signature_header

SECRET = "whsec_test"
BODY = json.dumps({"id": "evt_1", "seq": 1, "type": "test", "subscription_id": "sub_1", "created_at": "x", "data": {}}).encode()


def sign(payload: bytes, secret: str = SECRET, t: int = None) -> str:
    t = int(time.time()) if t is None else t
    digest = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={t},v1={digest}"


class VerifyEventTest(unittest.TestCase):
    def test_bytes_and_str(self):
        self.assertEqual(verify_event(BODY, sign(BODY), SECRET).id, "evt_1")
        self.assertEqual(verify_event(BODY.decode(), sign(BODY), SECRET).id, "evt_1")
        self.assertEqual(verify_event(bytearray(BODY), sign(BODY), SECRET).id, "evt_1")

    def test_rotation(self):
        self.assertEqual(verify_event(BODY, sign(BODY, "whsec_old"), ["whsec_new", "whsec_old"]).id, "evt_1")

    def test_rejections(self):
        with self.assertRaises(SignatureError):
            verify_event(BODY + b" ", sign(BODY), SECRET)
        with self.assertRaises(SignatureError):
            verify_event(BODY, sign(BODY, t=int(time.time()) - 3600), SECRET)
        with self.assertRaises(SignatureError):
            verify_event(BODY, "garbage", SECRET)
        with self.assertRaises(SignatureError):
            verify_event(BODY, "t=1,v1=é", SECRET)

    def test_configuration_errors(self):
        with self.assertRaises(TypeError):
            verify_event(json.loads(BODY), sign(BODY), SECRET)
        with self.assertRaises(TypeError):
            verify_event(BODY, sign(BODY), None)
        with self.assertRaises(TypeError):
            verify_event(BODY, sign(BODY), "")

    def test_header_parsing_matches_other_sdks(self):
        self.assertEqual(parse_signature_header("t=17,v1=a, v1=b"), (17, ["a", "b"]))
        self.assertEqual(parse_signature_header("t=+17,v1=a")[0], 0)


class SequenceTrackerTest(unittest.TestCase):
    def ev(self, seq):
        return CardanoEvent(id=f"e{seq}", type="test", subscription_id="sub", created_at="", data={}, seq=seq)

    def test_gap_then_fill(self):
        tracker = SequenceTracker({"sub": 1})
        self.assertEqual(tracker.check(self.ev(4)), (False, [2, 3]))
        tracker.commit(self.ev(4))
        self.assertEqual(tracker.cursor("sub"), 1)
        tracker.commit(self.ev(2))
        tracker.commit(self.ev(3))
        self.assertEqual(tracker.cursor("sub"), 4)
        self.assertEqual(tracker.check(self.ev(4)), (True, []))
        self.assertEqual(tracker.snapshot(), {"sub": 4})


class ClientTest(unittest.TestCase):
    def test_unreachable_is_api_error_with_status_0(self):
        client = LiqbeaconClient("http://127.0.0.1:9", "sk_test", timeout=2)
        with self.assertRaises(ApiError) as ctx:
            client.cursor("sub")
        self.assertEqual(ctx.exception.status, 0)

    def test_read_timeout_is_api_error(self):
        client = LiqbeaconClient("http://example.invalid", "sk_test")
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaises(ApiError) as ctx:
                client.cursor("sub")
        self.assertEqual((ctx.exception.status, ctx.exception.reason), (0, "timeout"))


if __name__ == "__main__":
    unittest.main()
