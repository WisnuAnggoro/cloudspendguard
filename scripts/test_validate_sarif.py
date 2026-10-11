"""Offline regression tests: python3 -m unittest discover -s scripts -p 'test_*.py'."""
import contextlib
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
import urllib.error
from unittest import mock

import certifi
import validate_sarif


class ValidateSarifTests(unittest.TestCase):
    def test_tls_verification_enabled(self):
        context = validate_sarif.schema_ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)

    def test_configured_roots_are_preserved(self):
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": certifi.where()}):
            with mock.patch.object(ssl, "create_default_context", wraps=ssl.create_default_context) as create:
                context = validate_sarif.schema_ssl_context()
                create.assert_called_once_with()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_validation_results(self):
        schema = {"type": "object", "required": ["version"], "properties": {"version": {"const": "2.1.0"}}}
        for version, want_code, label in [("2.1.0", 0, "valid"), ("invalid", 1, "INVALID")]:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "report.sarif"
                path.write_text(json.dumps({"version": version, "runs": []}), encoding="utf-8")
                output = io.StringIO()
                response = io.BytesIO(json.dumps(schema).encode("utf-8"))
                with mock.patch.object(validate_sarif.urllib.request, "urlopen", return_value=response) as request:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                        code = validate_sarif.main(str(path))
                self.assertEqual(code, want_code)
                self.assertIn(f": {label} against SARIF", output.getvalue())
                context = request.call_args.kwargs["context"]
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertTrue(context.check_hostname)

    def test_download_failure_returns_actionable_error(self):
        error = io.StringIO()
        with mock.patch.object(
            validate_sarif.urllib.request, "urlopen",
            side_effect=urllib.error.URLError("certificate verify failed"),
        ):
            with contextlib.redirect_stderr(error):
                code = validate_sarif.main("unused.sarif")
        self.assertEqual(code, 2)
        self.assertIn("TLS verification remains enabled", error.getvalue())
        self.assertIn("SSL_CERT_FILE", error.getvalue())


if __name__ == "__main__":
    unittest.main()
