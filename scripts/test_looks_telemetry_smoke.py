import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


spec = importlib.util.spec_from_file_location(
    "looks_smoke", Path(__file__).with_name("looks-telemetry-smoke.py")
)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)

KEY = "a" * 64
REFRESH = "private-refresh-credential"
ACCESS = "private-access-credential"
NEW_ACCESS = "private-new-access-credential"


class FakeHTTP:
    def __init__(self, wrong_alias=False, fail_batch=False, cleanup_error=False,
                 flat_mismatch=False, suppression_after=2):
        self.wrong_alias = wrong_alias
        self.fail_batch = fail_batch
        self.cleanup_error = cleanup_error
        self.flat_mismatch = flat_mismatch
        self.suppression_after = suppression_after
        self.calls = []
        self.denials = 0
        self.denied = False
        self.probes = 0

    def open(self, request, timeout):
        assert 0 < timeout <= 15
        payload = json.loads(request.data)
        authorization = request.get_header("Authorization")
        path = request.full_url.removeprefix("https://identity.test").removeprefix(
            "https://metrics.test"
        )
        self.calls.append((path, request, payload))
        status = 200
        if path == "/v1/public/installations":
            assert request.method == "POST" and authorization is None
            assert payload["product_id"] == "linka-looks"
            assert payload["platform"] == "windows"
            assert payload["preference"] == "allowed"
            assert payload["policy_version"] == "2026-07-22-v3"
            status = 201
            body = dict(payload, product="linka-looks", installation_key=KEY,
                        refresh_token=REFRESH, metrics_token=self.token(ACCESS))
        elif path == "/v1/public/installations/token":
            assert payload == {} and authorization == "Bearer " + REFRESH
            if self.denied:
                status, body = 403, {"error": "telemetry_denied"}
            else:
                body = dict(self.token(NEW_ACCESS), metrics_token=self.token(NEW_ACCESS),
                            product="linka-looks", installation_key="b" * 64 if self.wrong_alias else KEY)
                if self.flat_mismatch:
                    body["access_token"] = ACCESS
        elif path == "/v1/public/installations/telemetry-preference":
            assert request.method == "PUT" and authorization == "Bearer " + REFRESH
            assert payload["preference"] == "denied"
            assert payload["policy_version"] == "2026-07-22-v3"
            assert payload["recorded_at"] > self.calls[0][2]["recorded_at"]
            self.denials += 1
            if self.cleanup_error:
                status, body = 503, {"error": "secret raw error " + REFRESH}
            else:
                self.denied = True
                body = dict(payload, product="linka-looks", installation_key=KEY)
        elif path == "/v2/batches":
            assert request.method == "POST"
            assert request.get_header("Idempotency-key") == payload["batch_id"]
            assert payload["schema_version"] == 2
            assert payload["scope"] == {"product": "linka-looks", "subject_key": KEY}
            assert authorization in ("Bearer " + ACCESS, "Bearer " + NEW_ACCESS)
            record = payload["records"][0]
            assert record["app"]["build"] == "looks-backend-canary"
            if payload["stream"] == "outcome":
                assert record["kind"] == "utterance_completed"
                assert record["result"] == "completed" and record["mode"] == "standard"
            else:
                assert payload["stream"] == "product" and record["kind"] == "start"
            previous = [call for call in self.calls[:-1]
                        if call[0] == path and call[2]["batch_id"] == payload["batch_id"]]
            if previous:
                assert previous[0][1].data == request.data
            status = 202
            body = {"batch_id": payload["batch_id"], "accepted_records": 1, "replayed": bool(previous)}
            if self.fail_batch:
                status, body = 500, {"error": "secret raw error " + ACCESS}
            if self.denied:
                assert authorization == "Bearer " + NEW_ACCESS
                self.probes += 1
                # A completed ledger replay bypasses the suppression check.
                if not previous and self.probes >= self.suppression_after:
                    status, body = 403, {"error": "telemetry_suppressed"}
        else:
            raise AssertionError("unexpected URL")
        data = io.BytesIO(json.dumps(body).encode())
        if status >= 400:
            raise HTTPError(request.full_url, status, "private error", {}, data)
        data.status = status
        return data

    @staticmethod
    def token(access):
        return {"access_token": access, "token_type": "Bearer", "expires_at": "2099-01-01T00:00:00Z"}


class SmokeTests(unittest.TestCase):
    def invoke(self, fake, env=None):
        output = io.StringIO()
        with patch.dict(os.environ, env or {
            "IDENTITY_URL": "https://identity.test", "METRIC_URL": "https://metrics.test"
        }, clear=True), patch.object(smoke.urllib.request, "build_opener", return_value=fake), \
                patch.object(smoke.time, "sleep") as sleep, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = smoke.main()
        text = output.getvalue()
        for secret in (KEY, REFRESH, ACCESS, NEW_ACCESS, "secret raw error"):
            self.assertNotIn(secret, text)
        return code, [json.loads(line) for line in text.splitlines()], sleep

    def test_pipeline_and_safe_summary(self):
        fake = FakeHTTP()
        code, output, sleep = self.invoke(fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.denials, 1)
        self.assertEqual(fake.probes, 2)
        sleep.assert_called_once_with(1)
        summary = output[-1]
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["build"], "looks-backend-canary")
        records = [call[2]["records"][0] for call in fake.calls if call[0] == "/v2/batches"]
        self.assertEqual(set(summary["record_ids"]), {record["record_id"] for record in records})
        self.assertEqual({summary["session_id"]}, {record["app_session_id"] for record in records})
        batches = [call for call in fake.calls if call[0] == "/v2/batches"]
        self.assertEqual(batches[0][1].data, batches[1][1].data)
        self.assertNotEqual(batches[-1][1].data, batches[-2][1].data)
        self.assertEqual(summary["count"], 4)
        self.assertEqual(len(summary["record_ids"]), 5)
        self.assertEqual(batches[2][1].get_header("Authorization"), "Bearer " + NEW_ACCESS)
        self.assertEqual(batches[3][1].get_header("Authorization"), "Bearer " + NEW_ACCESS)

    def test_wrong_alias_fails_and_denies(self):
        fake = FakeHTTP(wrong_alias=True)
        code, output, _ = self.invoke(fake)
        self.assertEqual(code, 1)
        self.assertEqual(fake.denials, 1)
        self.assertEqual(output[-1]["status"], "failed")
        self.assertTrue(any(row["stage"] == "refresh" and row["status"] == "failed" for row in output))

    def test_flat_token_mismatch_fails_and_denies(self):
        fake = FakeHTTP(flat_mismatch=True)
        code, output, _ = self.invoke(fake)
        self.assertEqual(code, 1)
        self.assertTrue(fake.denied)
        self.assertTrue(any(row["stage"] == "refresh" and row["status"] == "failed" for row in output))

    def test_immediate_suppression_does_not_sleep(self):
        code, _, sleep = self.invoke(FakeHTTP(suppression_after=1))
        self.assertEqual(code, 0)
        sleep.assert_not_called()

    def test_suppression_timeout_fails_without_unbounded_wait(self):
        with patch.object(smoke.time, "monotonic", side_effect=[0, 0, 181]):
            code, output, sleep = self.invoke(FakeHTTP(suppression_after=100))
        self.assertEqual(code, 1)
        sleep.assert_not_called()
        self.assertTrue(any(row["stage"] == "suppression" and row["status"] == "failed" for row in output))

    def test_suppression_backoff_is_bounded(self):
        code, _, sleep = self.invoke(FakeHTTP(suppression_after=5))
        self.assertEqual(code, 0)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2, 3, 3])

    def test_completed_ledger_replays_before_suppression(self):
        fake = FakeHTTP()
        fake.denied = True
        canary = smoke.Canary()
        canary.key = KEY
        canary.metric = "https://metrics.test"
        canary.opener = fake
        probe = canary.batch("product", "start")
        status, body = canary.send_batch(probe, NEW_ACCESS)
        self.assertEqual(status, 202)
        self.assertIs(body["replayed"], False)
        status, body = canary.send_batch(probe, NEW_ACCESS)
        self.assertEqual(status, 202)
        self.assertIs(body["replayed"], True)
        status, body = canary.send_batch(canary.batch("product", "start"), NEW_ACCESS)
        self.assertEqual((status, body), (403, {"error": "telemetry_suppressed"}))

    def test_suppression_uses_fresh_batch_and_record_for_every_attempt(self):
        fake = FakeHTTP(suppression_after=3)
        with patch.object(smoke.time, "monotonic", side_effect=range(0, 1000, 10)):
            code, output, _ = self.invoke(fake)
        self.assertEqual(code, 0)
        probes = [call[2] for call in fake.calls if call[0] == "/v2/batches"][-fake.probes:]
        self.assertEqual(len(probes), 3)
        self.assertEqual(len({probe["batch_id"] for probe in probes}), 3)
        probe_ids = {probe["records"][0]["record_id"] for probe in probes}
        self.assertEqual(len(probe_ids), 3)
        summary = output[-1]
        self.assertTrue(probe_ids.issubset(summary["record_ids"]))
        self.assertEqual(len(summary["record_ids"]), 6)
        self.assertEqual(summary["count"], 5)

    def test_original_error_survives_cleanup_failure(self):
        fake = FakeHTTP(fail_batch=True, cleanup_error=True)
        code, output, _ = self.invoke(fake)
        self.assertEqual(code, 1)
        self.assertEqual(fake.denials, 1)
        self.assertTrue(any(row["stage"] == "cleanup" and row["status"] == "failed" for row in output))
        self.assertTrue(any(row["stage"] == "initial_batch" and row["status"] == "failed" for row in output))

    def test_cleanup_after_early_failure(self):
        fake = FakeHTTP(fail_batch=True)
        code, _, _ = self.invoke(fake)
        self.assertEqual(code, 1)
        self.assertTrue(fake.denied)

    def test_unsafe_urls_make_no_requests(self):
        for url in ("http://example.org", "https://user:pass@example.org", "https://example.org?q=1",
                    "https://example.org/#fragment", "file:///etc/passwd"):
            with self.subTest(url=url):
                fake = FakeHTTP()
                code, _, _ = self.invoke(fake, {"IDENTITY_URL": url, "METRIC_URL": "https://metrics.test"})
                self.assertEqual(code, 1)
                self.assertEqual(fake.calls, [])

    def test_http_loopback_and_https_urls_are_allowed(self):
        for url in ("https://example.org", "http://127.0.0.1:1234", "http://[::1]:1234", "http://localhost:1234"):
            with self.subTest(url=url):
                self.assertEqual(smoke.validate_url(url), url)

    def test_redirect_is_not_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://unrelated.invalid/credential-leak")
                self.end_headers()

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Redirect) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                opener = smoke.urllib.request.build_opener(smoke.NoRedirect())
                request = smoke.urllib.request.Request(
                    "http://127.0.0.1:" + str(server.server_port),
                    headers={"Authorization": "Bearer " + REFRESH},
                )
                with self.assertRaises(HTTPError) as raised:
                    opener.open(request, timeout=15)
                self.assertEqual(raised.exception.code, 302)
                raised.exception.close()
            finally:
                server.shutdown()
                worker.join()


if __name__ == "__main__":
    unittest.main()
