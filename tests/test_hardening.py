"""RC hardening tests: config validation, errors, logging, plugin SDK, caching.
Run: python -m unittest tests.test_hardening -q
"""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from glasscage import logging_setup
from glasscage.aakg import EdgeState, EdgeType, NodeType, PropertyGraph
from glasscage.config import validate_target_config, validate_trials
from glasscage.errors import AdapterError, ConfigError, GlasscageError, PluginError


class TestConfigValidation(unittest.TestCase):
    def test_missing_url(self):
        with self.assertRaises(ConfigError):
            validate_target_config({})

    def test_bad_scheme(self):
        with self.assertRaises(ConfigError):
            validate_target_config({"url": "ftp://x"})

    def test_bad_type(self):
        with self.assertRaises(ConfigError):
            validate_target_config({"url": "http://x", "headers": "nope"})

    def test_negative_timeout(self):
        with self.assertRaises(ConfigError):
            validate_target_config({"url": "http://x", "timeout": -1})

    def test_valid_passes(self):
        cfg = {"url": "https://api.example/chat", "headers": {"A": "b"}, "timeout": 10}
        self.assertEqual(validate_target_config(cfg), cfg)

    def test_trials(self):
        self.assertEqual(validate_trials(3), 3)
        with self.assertRaises(ConfigError):
            validate_trials(0)


class TestErrors(unittest.TestCase):
    def test_hierarchy(self):
        for cls in (ConfigError, PluginError, AdapterError):
            self.assertTrue(issubclass(cls, GlasscageError))

    def test_target_config_error_is_glasscage_error(self):
        from glasscage.target import HTTPChatTarget
        with self.assertRaises(GlasscageError):
            HTTPChatTarget({"url": "bad"})


class TestLogging(unittest.TestCase):
    def test_json_formatter_valid_json(self):
        stream = io.StringIO()
        logging_setup.configure(level="INFO", json_output=True, stream=stream)
        logging_setup.get_logger("test").info("hello world")
        line = stream.getvalue().strip().splitlines()[-1]
        obj = json.loads(line)
        self.assertEqual(obj["msg"], "hello world")
        self.assertEqual(obj["level"], "INFO")

    def test_get_logger_namespaced(self):
        self.assertTrue(logging_setup.get_logger("foo").name.startswith("glasscage"))

    def tearDown(self):
        logging_setup.configure(level="WARNING")  # reset


class TestPluginSDK(unittest.TestCase):
    def _dir(self):
        return os.path.join(os.path.dirname(__file__), "..", "plugins_example")

    def test_load_example_plugin(self):
        from glasscage import plugins
        from glasscage.probes import REGISTRY
        before = list(REGISTRY)
        n = plugins.load_plugins(self._dir(), strict=True)
        try:
            self.assertGreaterEqual(n, 1)
            names = {p.name for p in REGISTRY}
            self.assertIn("example-greeting-injection", names)
        finally:
            REGISTRY[:] = before  # avoid polluting other tests

    def test_missing_dir_returns_zero(self):
        from glasscage import plugins
        self.assertEqual(plugins.load_plugins("/no/such/dir"), 0)


class TestGraphCaching(unittest.TestCase):
    def _g(self):
        g = PropertyGraph()
        g.ensure(NodeType.USER, "u"); g.ensure(NodeType.SECRETS, "s")
        g.add_edge("User:u", EdgeType.ACCESSES, "Secrets:s", EdgeState.DEMONSTRATED)
        return g

    def test_cache_memoizes(self):
        g = self._g()
        calls = {"n": 0}
        def compute():
            calls["n"] += 1
            return 42
        self.assertEqual(g.cached("k", compute), 42)
        self.assertEqual(g.cached("k", compute), 42)
        self.assertEqual(calls["n"], 1)  # computed once

    def test_mutation_invalidates_cache(self):
        g = self._g()
        g.cached("k", lambda: "old")
        g.ensure(NodeType.LLM, "m")   # mutation clears cache
        self.assertEqual(g.cached("k", lambda: "new"), "new")


if __name__ == "__main__":
    unittest.main()


class TestPluginConsentCLI(unittest.TestCase):
    def test_cli_blocks_plugins_without_consent(self):
        import cli
        rc = cli.main(["--demo", "--plugins", os.path.join(os.path.dirname(__file__), "..",
                       "plugins_example"), "--out", "/tmp/glasscage_test_np"])
        self.assertEqual(rc, 2)  # refused without --allow-plugins

    def test_cli_allows_with_consent(self):
        import cli
        from glasscage.probes import REGISTRY
        before = list(REGISTRY)
        try:
            rc = cli.main(["--demo", "--plugins",
                           os.path.join(os.path.dirname(__file__), "..", "plugins_example"),
                           "--allow-plugins", "--out", "/tmp/glasscage_test_yp"])
            self.assertEqual(rc, 0)
        finally:
            REGISTRY[:] = before
