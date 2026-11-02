"""Run from the project root with: python -m unittest discover -s tests"""

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
        with self.assertRaises(SignatureError):
            verify_event(BODY, "t=" + "9" * 5000 + ",v1=ab", SECRET)

    def test_signed_but_invalid_body(self):
        for body in (b"not json", b"[]", b"{}", b"\xff"):
            with self.assertRaises(ValueError):
                verify_event(body, sign(body), SECRET)

    def test_configuration_errors(self):
        with self.assertRaises(TypeError):
            verify_event(json.loads(BODY), sign(BODY), SECRET)
        with self.assertRaises(TypeError):
            verify_event(BODY, sign(BODY), None)
        with self.assertRaises(TypeError):
            verify_event(BODY, sign(BODY), "")
        with self.assertRaises(TypeError):
            verify_event(BODY, sign(BODY), SECRET.encode())

    def test_header_parsing_matches_other_sdks(self):
        self.assertEqual(parse_signature_header("t=17,v1=a, v1=b"), (17, ["a", "b"]))
        self.assertEqual(parse_signature_header("t=+17,v1=a")[0], 0)


class SequenceTrackerTest(unittest.TestCase):
    def ev(self, seq):
        return CardanoEvent(id=f"e{seq}", type="test", subscription_id="sub", created_at="", data={}, seq=seq)

    def test_gap_then_fill(self):
        tracker = SequenceTracker({"sub": 1})
        self.assertEqual(tracker.check(self.ev(4)), (False, (2, 3)))
        tracker.commit(self.ev(4))
        self.assertEqual(tracker.cursor("sub"), 1)
        tracker.commit(self.ev(2))
        tracker.commit(self.ev(3))
        self.assertEqual(tracker.cursor("sub"), 4)
        self.assertEqual(tracker.check(self.ev(4)), (True, None))
        self.assertEqual(tracker.check(self.ev(5)), (False, None))
        self.assertEqual(tracker.snapshot(), {"sub": 4})

    def test_several_gaps(self):
        tracker = SequenceTracker({"sub": 1})
        tracker.commit(self.ev(4))
        # 2, 3, 5 and 6 are missing; 4 is committed but inside the range.
        self.assertEqual(tracker.check(self.ev(7)), (False, (2, 6)))
        tracker.commit(self.ev(6))
        self.assertEqual(tracker.check(self.ev(7)), (False, (2, 5)))
        tracker.commit(self.ev(2))
        tracker.commit(self.ev(3))
        self.assertEqual(tracker.check(self.ev(7)), (False, (5, 5)))

    def test_large_jump_is_cheap(self):
        tracker = SequenceTracker({"sub": 1})
        self.assertEqual(tracker.check(self.ev(10**12)), (False, (2, 10**12 - 1)))


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

    def test_rejects_non_http_base_url(self):
        with self.assertRaises(ValueError):
            LiqbeaconClient("file:///etc", "sk_test")

    def fake_response(self, body: bytes, status: int = 200):
        response = mock.MagicMock()
        response.status = status
        response.read.return_value = body
        response.__enter__.return_value = response
        return response

    def test_non_json_2xx_is_api_error(self):
        client = LiqbeaconClient("https://example.invalid", "sk_test")
        with mock.patch("urllib.request.urlopen", return_value=self.fake_response(b"<html>")):
            with self.assertRaises(ApiError) as ctx:
                client.cursor("sub")
        self.assertEqual(ctx.exception.status, 200)

    def test_sends_user_agent(self):
        client = LiqbeaconClient("https://example.invalid", "sk_test")
        with mock.patch("urllib.request.urlopen", return_value=self.fake_response(b"{}")) as urlopen:
            client.cursor("sub")
        self.assertTrue(urlopen.call_args[0][0].get_header("User-agent").startswith("liqbeacon-python/"))

    def test_pagination_that_does_not_advance(self):
        client = LiqbeaconClient("https://example.invalid", "sk_test")
        page = {"utxos": [], "next_cursor": "c1", "next_seq": 1}
        with mock.patch.object(client, "snapshot", return_value=page):
            with self.assertRaises(ApiError):
                client.load_snapshot("sub")


if __name__ == "__main__":
    unittest.main()
