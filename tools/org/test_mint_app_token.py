"""Isolated CLI controls; no keys, real tokens, or network requests are used."""
import contextlib
import io
import sys
import unittest
import urllib.error
from unittest.mock import patch

import mint_app_token


class MintAppTokenTests(unittest.TestCase):
    def invoke(self, *options, api_results):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ["mint_app_token.py", "--app-id", "123", "--key", "/unused/key", *options]
        with (
            patch.object(sys, "argv", args),
            patch.object(mint_app_token, "make_jwt", return_value="mock-jwt"),
            patch.object(mint_app_token, "api", side_effect=api_results) as api,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = mint_app_token.main()
        return status, stdout.getvalue(), stderr.getvalue(), api.call_args_list

    def test_default_discovers_transferred_repository_without_minting(self):
        with patch.object(mint_app_token.urllib.request, "urlopen") as network:
            status, stdout, stderr, calls = self.invoke(
                "--print-installation-id", api_results=[(200, {}), (200, {"id": 42})]
            )
        self.assertEqual(status, 0)
        self.assertEqual(stdout, "42\n")
        self.assertEqual(stderr, "")
        self.assertEqual(calls[1].args, ("GET", "/repos/whole-machine-works/RamenOS/installation"))
        network.assert_not_called()

    def test_explicit_repository_controls_discovery(self):
        with patch.object(mint_app_token.urllib.request, "urlopen") as network:
            status, stdout, stderr, calls = self.invoke(
                "--repo", "example/project", "--print-installation-id",
                api_results=[(200, {}), (200, {"id": 43})],
            )
        self.assertEqual((status, stdout, stderr), (0, "43\n", ""))
        self.assertEqual(calls[1].args, ("GET", "/repos/example/project/installation"))
        network.assert_not_called()

    def test_explicit_installation_skips_repository_discovery(self):
        with patch.object(mint_app_token.urllib.request, "urlopen") as network:
            status, stdout, stderr, calls = self.invoke(
                "--installation-id", "44", "--print-installation-id",
                api_results=[(200, {})],
            )
        self.assertEqual((status, stdout, stderr), (0, "44\n", ""))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args, ("GET", "/app"))
        network.assert_not_called()

    def test_failed_app_authentication_stops_before_discovery(self):
        with patch.object(mint_app_token.urllib.request, "urlopen") as network:
            status, stdout, stderr, calls = self.invoke(
                api_results=[(401, {"message": "Bad credentials"})]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("app authentication failed (HTTP 401)", stderr)
        self.assertEqual(len(calls), 1)
        network.assert_not_called()

    def test_missing_installation_stops_without_minting(self):
        with patch.object(mint_app_token.urllib.request, "urlopen") as network:
            status, stdout, stderr, calls = self.invoke(
                api_results=[(200, {}), (404, {"message": "Not Found"})]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("could not resolve installation for whole-machine-works/RamenOS (HTTP 404)", stderr)
        self.assertEqual(len(calls), 2)
        network.assert_not_called()

    def test_token_request_failure_is_nonzero_and_emits_no_token(self):
        failure = urllib.error.HTTPError(
            "https://api.github.com/app/installations/45/access_tokens", 403,
            "Forbidden", {}, io.BytesIO(b'{"message":"Forbidden"}'),
        )
        with patch.object(mint_app_token.urllib.request, "urlopen", side_effect=failure) as network:
            status, stdout, stderr, _ = self.invoke(
                "--installation-id", "45", api_results=[(200, {})]
            )
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("token mint failed (HTTP 403)", stderr)
        request = network.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/app/installations/45/access_tokens")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.data, b"{}")


if __name__ == "__main__":
    unittest.main()
