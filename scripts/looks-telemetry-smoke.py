"""Looks backend canary. Configure IDENTITY_URL and METRIC_URL; never logs credentials."""

from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


PRODUCT = "linka-looks"
POLICY = "2026-07-22-v3"
BUILD = "looks-backend-canary"
PLATFORM = "windows"


class SmokeError(Exception):
    pass


def require(condition):
    if not condition:
        raise SmokeError()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def validate_url(value):
    require(isinstance(value, str) and value and not any(c.isspace() for c in value))
    require(not any(c in value for c in ("?", "#", "\\")))
    parsed = urllib.parse.urlsplit(value)
    require(parsed.hostname and not parsed.username and not parsed.password)
    require("@" not in parsed.netloc and parsed.port != 0)
    loopback = parsed.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        pass
    require(parsed.scheme == "https" or (parsed.scheme == "http" and loopback))
    return value.rstrip("/")


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def report(stage, status, count=0, **summary):
    print(json.dumps(dict(stage=stage, status=status, count=count, **summary)), flush=True)


class Canary:
    def __init__(self):
        self.stage = "configuration"
        self.session_id = str(uuid.uuid4())
        self.record_ids = []
        self.accepted_ids = set()
        self.refresh = None
        self.key = None
        self.denied = False

    def request(self, base, path, method, body, credential=None, batch_id=None, timeout=15):
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        if batch_id:
            headers["Idempotency-Key"] = batch_id
        request = urllib.request.Request(base + path, data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code if isinstance(response, urllib.error.HTTPError) else response.status
            raw = response.read(65537)
        require(len(raw) <= 65536)
        result = json.loads(raw)
        require(isinstance(result, dict))
        return status, result

    def identity_request(self, path, method, body, credential=None):
        return self.request(self.identity, "/v1/public/installations" + path,
                            method, encode(body), credential)

    def same_installation(self, body):
        require(body.get("product") == PRODUCT and body.get("installation_key") == self.key)

    def access_token(self, body):
        require(isinstance(body, dict) and body.get("token_type") == "Bearer")
        access = body.get("access_token")
        require(isinstance(access, str) and access and not any(c.isspace() for c in access))
        expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
        require(expires > datetime.now(timezone.utc))
        return access

    def batch(self, stream, kind, **fields):
        record_id = str(uuid.uuid4())
        self.record_ids.append(record_id)
        now = timestamp()
        batch_id = str(uuid.uuid4())
        body = encode({
            "schema_version": 2, "batch_id": batch_id,
            "scope": {"product": PRODUCT, "subject_key": self.key},
            "stream": stream, "sent_at": now,
            "records": [{
                "record_id": record_id, "occurred_at": now, "kind": kind,
                "app_session_id": self.session_id,
                "app": {"version": "0.0.0", "build": BUILD, "platform": PLATFORM,
                        "os_version": "canary", "locale": "ru-RU"},
                **fields,
            }],
        })
        return batch_id, record_id, body

    def send_batch(self, batch, access, timeout=15):
        batch_id, _, body = batch
        return self.request(self.metric, "/v2/batches", "POST", body, access, batch_id, timeout)

    def accepted(self, batch, status, body, replayed):
        require(status == 202 and body.get("batch_id") == batch[0])
        require(type(body.get("accepted_records")) is int and body["accepted_records"] == 1)
        require(body.get("replayed") is replayed)
        self.accepted_ids.add(batch[1])
        report(self.stage, "ok", 1)

    def deny(self):
        recorded_at = max(datetime.now(timezone.utc),
                          datetime.fromisoformat(self.registered_at.replace("Z", "+00:00"))
                          + timedelta(milliseconds=1))
        status, body = self.identity_request("/telemetry-preference", "PUT", {
            "preference": "denied", "policy_version": POLICY,
            "recorded_at": recorded_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }, self.refresh)
        require(status == 200)
        self.same_installation(body)
        require(body.get("preference") == "denied" and body.get("policy_version") == POLICY)
        self.denied = True

    def run(self):
        self.identity = validate_url(os.environ.get("IDENTITY_URL"))
        self.metric = validate_url(os.environ.get("METRIC_URL"))
        self.opener = urllib.request.build_opener(NoRedirect())
        try:
            self.pipeline()
        finally:
            if self.refresh and not self.denied:
                original_error = sys.exc_info()[0] is not None
                try:
                    self.deny()
                    report("cleanup", "ok")
                except Exception:
                    report("cleanup", "failed")
                    if not original_error:
                        self.stage = "cleanup"
                        raise SmokeError() from None

    def pipeline(self):
        self.stage = "registration"
        self.registered_at = timestamp()
        status, body = self.identity_request("", "POST", {
            "request_id": str(uuid.uuid4()), "product_id": PRODUCT, "platform": PLATFORM,
            "preference": "allowed", "policy_version": POLICY, "recorded_at": self.registered_at,
        })
        # Save the credential before validating the response so failures still attempt denial.
        credential = body.get("refresh_token")
        if isinstance(credential, str) and credential:
            self.refresh = credential
        self.key = body.get("installation_key")
        require(status == 201 and self.refresh)
        require(isinstance(self.key, str) and re.fullmatch(r"[0-9a-f]{64}", self.key))
        self.same_installation(body)
        require(body.get("platform") == PLATFORM and body.get("preference") == "allowed")
        require(body.get("policy_version") == POLICY)
        access = self.access_token(body.get("metrics_token"))
        report(self.stage, "ok")

        self.stage = "initial_batch"
        initial = self.batch("product", "start")
        self.accepted(initial, *self.send_batch(initial, access), replayed=False)
        self.stage = "replay"
        self.accepted(initial, *self.send_batch(initial, access), replayed=True)

        self.stage = "refresh"
        status, body = self.identity_request("/token", "POST", {}, self.refresh)
        require(status == 200)
        self.same_installation(body)
        access = self.access_token(body)
        nested = body.get("metrics_token")
        self.access_token(nested)
        require(all(body[field] == nested[field] for field in ("access_token", "token_type", "expires_at")))
        report(self.stage, "ok")

        self.stage = "refreshed_batch"
        renewed = self.batch("product", "start")
        self.accepted(renewed, *self.send_batch(renewed, access), replayed=False)
        self.stage = "outcome"
        outcome = self.batch("outcome", "utterance_completed", result="completed", mode="standard")
        self.accepted(outcome, *self.send_batch(outcome, access), replayed=False)

        self.stage = "denial"
        self.deny()
        report(self.stage, "ok")
        self.stage = "denied_refresh"
        status, body = self.identity_request("/token", "POST", {}, self.refresh)
        require(status == 403 and body.get("error") == "telemetry_denied")
        report(self.stage, "ok")

        self.stage = "suppression"
        deadline = time.monotonic() + 180
        delay = 1
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            # Completed batch replays bypass suppression, so each probe must be new.
            probe = self.batch("product", "start")
            status, body = self.send_batch(probe, access, timeout=min(15, remaining))
            if status == 403:
                require(body.get("error") == "telemetry_suppressed")
                report(self.stage, "ok")
                return
            self.accepted(probe, status, body, replayed=False)
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            time.sleep(min(delay, remaining))
            delay = min(delay + 1, 3)


def main():
    canary = Canary()
    status = "ok"
    try:
        canary.run()
    except Exception:
        # Never expose exception messages, URLs, response bodies, or credentials.
        report(canary.stage, "failed")
        status = "failed"
    report("summary", status, len(canary.accepted_ids), record_ids=canary.record_ids,
           session_id=canary.session_id, build=BUILD)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
