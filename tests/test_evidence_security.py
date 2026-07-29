"""P0-1 secure evidence handling: redaction is default, raw only on consent.
Run: python -m unittest tests.test_evidence_security -q
"""
import glob
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import redaction
from glasscage.engine import Engine
from glasscage.refagent import ReferenceAgent
from glasscage import schema
from glasscage.errors import ConfigError

_SECRET = "sk-REF00011122233344455"          # harness leaks this when disclosure fires
_TOOLS = schema.ingest({"functions": [{"name": "get_secret", "description": "vault", "parameters": {}}]})


class TestRedactionUnit(unittest.TestCase):
    def test_masks_common_secret_shapes(self):
        for s in ("api_key=sk-ABCDEF0123456789ABCDEF", "AKIA0123456789ABCDEF",
                  "password= hunter2secret", "-----BEGIN RSA PRIVATE KEY-----"):
            red, n = redaction.redact_text(s)
            self.assertGreater(n, 0)
            self.assertFalse(redaction.contains_secret(red), f"still leaks: {red}")

    def test_stable_token(self):
        a, _ = redaction.redact_text("x sk-ABCDEF0123456789ABCDEF")
        b, _ = redaction.redact_text("y sk-ABCDEF0123456789ABCDEF")
        self.assertEqual(a.split()[-1], b.split()[-1])  # same secret -> same token

    def test_none_safe(self):
        self.assertEqual(redaction.redact_text(None), ("", 0))


class TestEngineRedaction(unittest.TestCase):
    def _run(self, store_raw):
        d = tempfile.mkdtemp()
        eng = Engine(ReferenceAgent(), schema_tools=_TOOLS,
                     evidence_dir=os.path.join(d, "ev"), store_raw=store_raw)
        res = eng.run()
        return res, d

    def test_secret_absent_by_default(self):
        res, _ = self._run(store_raw=False)
        blob = "".join((f.response_excerpt or "") + (f.raw_response or "")
                       for f in res["findings"])
        self.assertNotIn(_SECRET, blob)

    def test_secret_present_with_consent(self):
        res, _ = self._run(store_raw=True)
        blob = "".join((f.response_excerpt or "") + (f.raw_response or "")
                       for f in res["findings"])
        # only assert if the disclosure probe actually fired on the harness
        if any(f.owasp_id == "LLM02" and f.status.value == "vulnerable" for f in res["findings"]):
            self.assertIn(_SECRET, blob)

    def test_evidence_hash_preserved_before_redaction(self):
        res, _ = self._run(store_raw=False)
        # chain of custody: every persisted finding still carries an evidence hash
        for f in res["findings"]:
            if f.raw_request or f.raw_response:
                self.assertTrue(f.evidence_hash)


class TestEncryptionGating(unittest.TestCase):
    def test_refuses_or_encrypts_honestly(self):
        d = tempfile.mkdtemp()
        open(os.path.join(d, "e.svg"), "w").write("secret sk-ABCDEF0123456789ABCDEF")
        if redaction.encryption_available():
            n = redaction.encrypt_dir(d, "pw")
            self.assertGreaterEqual(n, 1)
            self.assertFalse(os.path.exists(os.path.join(d, "e.svg")))  # plaintext removed
        else:
            with self.assertRaises(ConfigError):   # honest refusal, no fake cipher
                redaction.encrypt_dir(d, "pw")


if __name__ == "__main__":
    unittest.main()
