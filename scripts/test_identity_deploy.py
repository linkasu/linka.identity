"""Deployment contract checks; execute only extracted bash with a local YC stub."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/deploy-yc.yml").read_text()


def step(name):
    match = re.search(
        r"^      - name: " + re.escape(name) + r"\n(.*?)(?=^      - |\Z)",
        WORKFLOW,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"missing step: {name}")
    return match.group(1)


def script(name):
    body = step(name).split("        run: |\n", 1)[1]
    return "\n".join(line[10:] for line in body.splitlines())


class IdentityDeployTests(unittest.TestCase):
    def test_manual_only_and_no_mutations_or_automatic_restore(self):
        triggers = WORKFLOW.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"^  (\w+):", triggers, re.MULTILINE), ["workflow_dispatch"])
        self.assertIn("default: normal", triggers)
        self.assertNotIn("workflow_run", WORKFLOW)
        self.assertNotIn("serverless container rollback", WORKFLOW)
        self.assertNotIn("docker build ", WORKFLOW)
        self.assertNotIn("looks-telemetry-smoke.py", WORKFLOW)
        self.assertNotIn("/v1/public/installations", WORKFLOW)
        self.assertIn("No automatic rollback or schema mutation", WORKFLOW)
        self.assertIn("ref: main", WORKFLOW.split("\n  deploy:\n", 1)[0])

    def test_exact_ref_is_validated_before_checkout_and_yc(self):
        sha = "a" * 40
        for ref, tag, mode, valid in [
            (sha, "sha-" + sha, "normal", True),
            (sha, "sha-" + sha, "maintenance", True),
            ("main", "sha-" + sha, "normal", False),
            ("A" * 40, "sha-" + "A" * 40, "normal", False),
            (sha, "sha-" + "b" * 40, "normal", False),
            (sha + "\n", "sha-" + sha + "\n", "normal", False),
            ("$(exit 0)", "sha-$(exit 0)", "normal", False),
            (sha, "sha-" + sha, "other", False),
        ]:
            with self.subTest(ref=ref, mode=mode):
                result = subprocess.run(
                    ["bash", "-eo", "pipefail", "-c", script("Validate immutable inputs")],
                    env={**os.environ, "DEPLOY_REF": ref, "IMAGE_TAG": tag,
                         "DEPLOY_MODE": mode, "IDENTITY_PUBLIC_URL": "https://example.invalid"},
                    capture_output=True,
                )
                self.assertEqual(result.returncode == 0, valid)
        deploy = WORKFLOW.split("  deploy:\n", 1)[1]
        self.assertLess(deploy.index("Validate immutable inputs"), deploy.index("actions/checkout"))
        self.assertLess(deploy.index("Require successful CI"), deploy.index("Install YC CLI"))
        self.assertIn("ref: ${{ env.DEPLOY_REF }}", deploy)
        for body in re.findall(r"^        run: \|\n((?:          .*\n|\n)*)", WORKFLOW, re.MULTILINE):
            self.assertNotIn("${{", body)
            syntax = subprocess.run(["bash", "-n"], input=body, capture_output=True, text=True)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_ci_exact_success_and_schema_read_only_gate(self):
        ci = step("Require successful CI for exact commit")
        self.assertIn("GH_TOKEN: ${{ github.token }}", ci)
        self.assertIn('--workflow ci.yml --commit "$DEPLOY_REF"', ci)
        self.assertIn('.headSha == $ref and .conclusion == "success"', ci)
        self.assertIn("actions: read", WORKFLOW)
        self.assertIn("const Version = uint64(3)", WORKFLOW)
        schema = step("Check schema from exact image digest without migration")
        self.assertIn("if: inputs.mode == 'normal'", schema)
        self.assertIn('"$IMAGE_REF" -check', schema)
        self.assertIn("target=/run/secrets/ydb-sa.json,readonly", schema)
        self.assertEqual(WORKFLOW.count("--entrypoint /usr/local/bin/schema"), 1)
        self.assertLess(WORKFLOW.index("Check schema from exact"), WORKFLOW.index("name: Deploy immutable revision"))

    def test_mode_specific_operations(self):
        for name in ["Apply and verify gateway rate limit",
                     "Drain required workers through direct IAM invocation",
                     "Production readiness and JWKS smoke"]:
            self.assertIn("if: inputs.mode == 'normal'", step(name))
        maintenance = step("Verify maintenance health and unavailable readiness")
        self.assertIn("if: inputs.mode == 'maintenance'", maintenance)
        self.assertIn('.mode == "maintenance"', maintenance)
        self.assertIn('"$health_status" == 200', maintenance)
        self.assertIn("== 503", maintenance)
        self.assertNotIn("workers/tick", maintenance)
        self.assertIn("SECONDS < deadline", maintenance)
        self.assertIn("SECONDS < deadline", step("Drain required workers through direct IAM invocation"))
        self.assertIn('"$IDENTITY_PUBLIC_URL/internal/workers/tick")" = 404', WORKFLOW)

    def deploy_args(self, mode, **overrides):
        # All files and fake credentials stay inside this project; no real YC calls.
        with tempfile.TemporaryDirectory(prefix=".deploy-test-", dir=ROOT) as directory:
            home = Path(directory)
            yc = home / "yandex-cloud/bin/yc"
            yc.parent.mkdir(parents=True)
            yc.write_text('#!/usr/bin/env python3\nimport json, os, sys\n'
                          'open(os.environ["TEST_YC_ARGS"], "w").write(json.dumps(sys.argv[1:]))\n')
            yc.chmod(0o700)
            output = home / "args.json"
            env = {**os.environ, "HOME": str(home), "TEST_YC_ARGS": str(output),
                   "DEPLOY_MODE": mode, "IMAGE_REF": "image@sha256:exact", "YC_RUNTIME_SA_ID": "runtime"}
            for key in re.findall(r"^          (\w+):", step("Deploy immutable revision"), re.MULTILINE):
                env.setdefault(key, "")
            if mode == "normal":
                env.update({key: "configured" for key in (
                    "YDB_ENDPOINT", "YDB_DATABASE", "EMAIL_KEY_ACTIVE_ID", "PUBLIC_INSTALLATION_PRODUCTS",
                    "PUBLIC_INSTALLATION_POLICY_VERSION", "YC_LOCKBOX_SECRET_ID", "YC_LOCKBOX_SECRET_VERSION_ID")})
                env.update(PUBLIC_ACCOUNT_ENABLED="false", PUBLIC_ACCOUNT_POLICY_VERSION="product-registration-v1",
                           PUBLIC_ACCOUNT_OTP_KEY_ID="otp-v1")
            env.update(overrides)
            result = subprocess.run(["bash", "-eo", "pipefail", "-c", script("Deploy immutable revision")],
                                    env=env, capture_output=True, text=True)
            return result, json.loads(output.read_text()) if output.exists() else None

    def test_maintenance_has_only_minimal_runtime_env_and_no_secret_refs(self):
        result, args = self.deploy_args("maintenance")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--secret", args)
        environments = [args[i + 1] for i, arg in enumerate(args) if arg == "--environment"]
        self.assertEqual(environments, ["HTTP_ADDR=:8080,DEPLOYMENT_ENVIRONMENT=production",
                                        "IDENTITY_MAINTENANCE_MODE=true"])
        self.assertIn("runtime", args)

    def test_normal_preserves_core_refs_and_fixed_budget(self):
        policies = 'one=v1;two=v2;$(exit 99)'
        result, args = self.deploy_args("normal", PUBLIC_ADDITIONAL_POLICIES=policies)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PUBLIC_INSTALLATION_ADDITIONAL_POLICIES=" + policies, args)
        self.assertIn("PUBLIC_ACCOUNT_PRODUCTS=", args)
        combined = " ".join(args)
        self.assertIn("IDENTITY_MAINTENANCE_MODE=false", combined)
        self.assertIn("PUBLIC_ACCOUNT_DAILY_LIMIT=200", combined)
        self.assertNotIn("vars.PUBLIC_ACCOUNT_DAILY_LIMIT", WORKFLOW)
        self.assertEqual(args.count("--secret"), 6)
        for key in ("workloads_json", "products_json", "pairwise_id_key_base64", "email_yc_kms_keys_json",
                    "blind_index_keys_json", "token_signing_keys_json"):
            self.assertIn("key=" + key, combined)
        self.assertNotIn("key=public_account_", combined)

    def test_i1_secret_refs_are_conditional_and_required(self):
        required = dict(I1_LOCKBOX_SECRET_ID="i1", I1_LOCKBOX_VERSION_ID="version",
                        PUBLIC_ACCOUNT_SMTP_ADDR="smtp.example:587", PUBLIC_ACCOUNT_SMTP_FROM="sender@example.invalid")
        for missing in required:
            with self.subTest(missing=missing):
                result, args = self.deploy_args("normal", PUBLIC_ACCOUNT_ENABLED="true", **{**required, missing: ""})
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(args)
        result, args = self.deploy_args("normal", PUBLIC_ACCOUNT_ENABLED="true", **required)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args.count("--secret"), 9)
        for env, key in [("PUBLIC_ACCOUNT_OTP_KEY_BASE64", "public_account_otp_key_base64"),
                         ("PUBLIC_ACCOUNT_SMTP_USER", "public_account_smtp_user"),
                         ("PUBLIC_ACCOUNT_SMTP_PASSWORD", "public_account_smtp_password")]:
            self.assertIn(f"environment-variable={env},id=i1,version-id=version,key={key}", args)
        for name in ("PUBLIC_ACCOUNT_ENABLED", "PUBLIC_ACCOUNT_POLICY_VERSION", "PUBLIC_ACCOUNT_OTP_KEY_ID"):
            self.assertRegex(step("Deploy immutable revision"), name + r": \$\{\{ vars\." + name + r" \|\| '")


if __name__ == "__main__":
    unittest.main()
