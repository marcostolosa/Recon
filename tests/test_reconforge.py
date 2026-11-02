import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from reconforge import (
    HTMLLinks,
    Recon,
    Scope,
    Store,
    Throttle,
    build_parser,
    hostnorm,
    score,
)


class TestReconForge(unittest.TestCase):
    def test_01_hostnorm(self):
        self.assertEqual(hostnorm("Example.COM."), "example.com")
        self.assertEqual(hostnorm("sub.têst.org"), "sub." + "têst".encode("idna").decode("ascii") + ".org")
        with self.assertRaises(ValueError):
            hostnorm("")
        with self.assertRaises(ValueError):
            hostnorm("-invalid.com")
        with self.assertRaises(ValueError):
            hostnorm("bad..domain.com")

    def test_02_scope_allowed_host(self):
        scope_subs = Scope("example.com", include_subdomains=True, excludes=["internal.example.com"])
        self.assertTrue(scope_subs.allowed_host("example.com"))
        self.assertTrue(scope_subs.allowed_host("api.example.com"))
        self.assertFalse(scope_subs.allowed_host("internal.example.com"))
        self.assertFalse(scope_subs.allowed_host("sub.internal.example.com"))
        self.assertFalse(scope_subs.allowed_host("attacker.com"))
        self.assertFalse(scope_subs.allowed_host("notexample.com"))

        scope_exact = Scope("example.com", include_subdomains=False, excludes=[])
        self.assertTrue(scope_exact.allowed_host("example.com"))
        self.assertFalse(scope_exact.allowed_host("api.example.com"))

    def test_03_scope_url_normalization(self):
        scope = Scope("example.com", include_subdomains=True, excludes=[])
        normalized = scope.url("https://API.Example.com:443/v1/users?b=2&a=1#fragment")
        self.assertEqual(normalized, "https://api.example.com/v1/users?a=1&b=2")

        relative = scope.url("/api/data", base="https://example.com/login")
        self.assertEqual(relative, "https://example.com/api/data")

    def test_04_scope_rejection(self):
        scope = Scope("example.com", include_subdomains=True, excludes=["corp.example.com"])
        self.assertIsNone(scope.url("http://evil.com/"))
        self.assertIsNone(scope.url("https://corp.example.com/"))
        self.assertIsNone(scope.url("ftp://example.com/test"))
        self.assertIsNone(scope.url("https://user:pass@example.com/"))
        self.assertIsNone(scope.url("https://example.com:8443/"))

    def test_05_score_priority(self):
        s1, tags1 = score("https://example.com/api/v1/users")
        self.assertIn("api", tags1)
        self.assertGreaterEqual(s1, 50)

        s2, tags2 = score("https://example.com/admin/dashboard?cmd=id")
        self.assertIn("admin", tags2)
        self.assertIn("parameterized", tags2)
        self.assertIn("high_value_param", tags2)
        self.assertGreater(s2, s1)

        s3, tags3 = score("https://example.com/assets/app.js")
        self.assertIn("javascript", tags3)

    def test_06_store_sqlite(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "state.sqlite"
            store = Store(db_path, max_urls=100)

            store.host("api.example.com", "subfinder")
            store.host("api.example.com", "crtsh")
            sources = store.conn.execute("SELECT sources FROM hosts WHERE host='api.example.com'").fetchone()[0]
            self.assertEqual(sources, "crtsh,subfinder")

            added = store.url("https://api.example.com/api", "seed", probe=True)
            self.assertTrue(added)
            self.assertEqual(len(store.pending(10)), 1)

            store.finish("https://api.example.com/api", {"status": 200, "bytes": 1234})
            self.assertEqual(len(store.pending(10)), 0)

            store.secret("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", "https://api.example.com/bundle.js", 12)
            self.assertEqual(store.count("secret_indicators"), 1)
            store.conn.close()

    def test_07_throttle_rate_and_slow(self):
        async def run_throttle():
            t = Throttle(rate=50.0, max_requests=2)
            self.assertTrue(await t.take("example.com"))
            self.assertTrue(await t.take("example.com"))
            self.assertFalse(await t.take("example.com"))

        asyncio.run(run_throttle())

    def test_08_html_and_form_parsing(self):
        html = """
        <html>
            <head><link rel="stylesheet" href="/style.css"></head>
            <body>
                <a href="/dashboard">Dashboard</a>
                <script src="/js/app.js"></script>
                <form action="/login" method="POST"><input name="user"></form>
                <form action="/search" method="GET"><input name="q"></form>
            </body>
        </html>
        """
        parser = HTMLLinks()
        parser.feed(html)
        self.assertIn("/style.css", parser.links)
        self.assertIn("/dashboard", parser.links)
        self.assertIn("/js/app.js", parser.links)
        self.assertEqual(len(parser.forms), 2)
        self.assertEqual(parser.forms[0]["method"], "POST")
        self.assertEqual(parser.forms[1]["method"], "GET")

    def test_09_js_and_json_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            parser = build_parser()
            args = parser.parse_args(["example.com", "--out", td])
            recon = Recon(args)

            js_code = """
            const api_url = '/api/v2/auth';
            fetch('https://example.com/internal/profile');
            const key = "AKIA1111111111111111";
            //# sourceMappingURL=/app.js.map
            """
            recon.analyze_js("https://example.com/app.js", js_code)

            urls = [r[0] for r in recon.store.conn.execute("SELECT url FROM urls")]
            self.assertIn("https://example.com/api/v2/auth", urls)
            self.assertIn("https://example.com/internal/profile", urls)
            self.assertIn("https://example.com/app.js.map", urls)
            self.assertEqual(recon.store.count("secret_indicators"), 1)

            # JSON OpenAPI path extraction
            openapi_payload = json.dumps({"paths": {"/api/v1/payments": {}, "/api/v1/checkout": {}}}).encode()
            recon.extract("https://example.com/openapi.json", "application/json", openapi_payload)
            urls = [r[0] for r in recon.store.conn.execute("SELECT url FROM urls")]
            self.assertIn("https://example.com/api/v1/payments", urls)

            recon.store.conn.close()

    def test_10_resume_config_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            parser = build_parser()
            args1 = parser.parse_args(["example.com", "--exclude", "b.example.com", "--exclude", "a.example.com", "--out", td])
            recon1 = Recon(args1)

            args2 = parser.parse_args(["example.com", "--exclude", "a.example.com", "--exclude", "b.example.com", "--out", td])
            recon2 = Recon(args2)

            # Both should have identical scope_config regardless of argument CLI order
            self.assertEqual(recon1.scope_config(), recon2.scope_config())
            recon1.store.conn.close()
            recon2.store.conn.close()


if __name__ == "__main__":
    unittest.main()
