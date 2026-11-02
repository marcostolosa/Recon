import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from unittest.mock import patch

from reconforge import (
    TAKEOVER_FINGERPRINTS,
    HTMLLinks,
    Recon,
    Scope,
    Store,
    Throttle,
    build_parser,
    apply_full_preset,
    check_system_tools,
    hostnorm,
    injection_classes,
    install_missing_tool,
    is_cache_buster,
    required_tools_for_args,
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
        self.assertEqual(normalized, "https://api.example.com/v1/users?b=2&a=1")

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


    def test_11_meta_persistence(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "state.sqlite"
            store = Store(db_path, max_urls=100)
            self.assertEqual(store.get_int("requests_total", 0), 0)
            store.set_int("requests_total", 42)
            store.set_int("requests_total", 99)  # upsert overwrites
            store.commit()
            store.conn.close()
            reopened = Store(db_path, max_urls=100)
            self.assertEqual(reopened.get_int("requests_total", 0), 99)
            reopened.conn.close()

    def test_12_resume_honours_cumulative_budget(self):
        with tempfile.TemporaryDirectory() as td:
            parser = build_parser()
            args = parser.parse_args(["example.com", "--out", td])
            recon = Recon(args)
            recon.gate.count = 123
            recon.probed = 45
            recon.export()
            recon.store.conn.close()
            # A fresh run against the same output resumes the counters, not from zero
            recon2 = Recon(parser.parse_args(["example.com", "--out", td]))
            self.assertEqual(recon2.prior_requests, 123)
            self.assertEqual(recon2.gate.count, 123)
            self.assertEqual(recon2.probed, 45)
            recon2.store.conn.close()

    def test_13_parse_identities(self):
        with tempfile.TemporaryDirectory() as td:
            parser = build_parser()
            args = parser.parse_args(
                ["example.com", "--out", td,
                 "--identity", "A:Authorization: Bearer tokA",
                 "--identity", "A:X-Trace: 1",
                 "--identity", "B:Authorization: Bearer tokB"]
            )
            recon = Recon(args)
            identities = recon.parse_identities()
            self.assertEqual(set(identities), {"A", "B"})
            self.assertEqual(identities["A"]["authorization"], "Bearer tokA")
            self.assertEqual(identities["A"]["x-trace"], "1")
            self.assertEqual(identities["B"]["authorization"], "Bearer tokB")
            recon.store.conn.close()

    def test_14_takeover_fingerprint_matches(self):
        github = b"<html><body>There isn't a GitHub Pages site here.</body></html>"
        matched = [svc for svc, rx in TAKEOVER_FINGERPRINTS if rx.search(github)]
        self.assertIn("github_pages", matched)
        benign = b"<html><body>Welcome to our homepage</body></html>"
        self.assertEqual([svc for svc, rx in TAKEOVER_FINGERPRINTS if rx.search(benign)], [])

    def test_15_max_body_clamped_to_20mb(self):
        with tempfile.TemporaryDirectory() as td:
            import reconforge
            parser = reconforge.build_parser()
            args = parser.parse_args(["example.com", "--out", td, "--max-body", "999000000"])
            recon = Recon(args)
            self.assertEqual(args.max_body, 20_000_000)
            asyncio.run(recon.aclose())

    def test_16_classify_url_routes_injection_tools(self):
        with tempfile.TemporaryDirectory() as td:
            recon = Recon(build_parser().parse_args(["example.com", "--out", td]))
            hits, names = recon.classify_url("https://example.com/item?id=5&redirect=/x&q=hi")
            self.assertIn("sqli", hits)          # id -> sqlmap/ghauri
            self.assertIn("ssrf_redirect", hits)  # redirect -> nuclei-ssrf/manual
            self.assertIn("xss", hits)            # q -> dalfox
            self.assertIn("sqlmap", hits["sqli"])
            self.assertIn("dalfox", hits["xss"])
            # a boring param routes to nothing
            empty, _ = recon.classify_url("https://example.com/x?totally_random_param=1")
            self.assertEqual(empty, {})
            recon.store.conn.close()

    def test_17_scan_profile_depth(self):
        with tempfile.TemporaryDirectory() as td:
            scan_dir = Path(td) / "scanners"
            scan_dir.mkdir()
            deep = Recon(build_parser().parse_args(["example.com", "--out", td, "--scan-profile", "deep"]))
            argv = deep._scan_argv("sqlmap", "https://example.com/a?id=1", scan_dir)
            self.assertIn("--level=5", argv)
            self.assertIn("--risk=3", argv)
            self.assertNotIn("--random-agent", argv)
            self.assertIn("--ignore-redirects", argv)
            deep.store.conn.close()
            safe = Recon(build_parser().parse_args(["example.com", "--out", td, "--scan-profile", "safe"]))
            argv = safe._scan_argv("sqlmap", "https://example.com/a?id=1", scan_dir)
            self.assertIn("--level=1", argv)
            self.assertNotIn("--random-agent", argv)
            safe.store.conn.close()

    def test_18_check_and_required_tools(self):
        report = check_system_tools()
        self.assertIn("subfinder", report)
        self.assertIn("sqlmap", report)
        self.assertIn("dnspython", report)
        args = build_parser().parse_args(["example.com", "--katana", "--ffuf", "--scanners", "sqlmap"])
        needed = required_tools_for_args(args)
        self.assertIn("subfinder", needed)
        self.assertIn("gau", needed)
        self.assertIn("katana", needed)
        self.assertIn("ffuf", needed)
        self.assertIn("sqlmap", needed)
        self.assertIn("dnspython", needed)

    def test_19_install_missing_tool_invokes_installer(self):
        calls = []

        def fake_which(cmd):
            if cmd == "go":
                return "/usr/bin/go"
            if cmd == "subfinder":
                return "/home/user/go/bin/subfinder" if calls else None
            return None

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return None

        with patch("reconforge.shutil.which", side_effect=fake_which), patch("reconforge.subprocess.run", side_effect=fake_run):
            ok = install_missing_tool("subfinder", timeout=30)
            self.assertTrue(ok)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1], "install")


class TestScanTargetingFixes(unittest.TestCase):
    def test_injectable_outranks_cache_buster_js(self):
        # Bug B regression: a SQLi endpoint must outrank a cache-busted JS bundle,
        # so the probe budget and scan planner reach it first.
        inj_score, inj_tags = score("http://testphp.vulnweb.com/listproducts.php?cat=1")
        js_score, js_tags = score("http://rest.vulnweb.com/docs/api_data.js?v=1596328976710")
        self.assertIn("injectable", inj_tags)
        self.assertIn("sqli", inj_tags)
        self.assertIn("cache_buster", js_tags)
        self.assertNotIn("javascript", js_tags)       # cache-buster suppresses JS bonus
        self.assertNotIn("parameterized", js_tags)
        self.assertGreater(inj_score, js_score)

    def test_real_js_still_scores_as_javascript(self):
        s, tags = score("http://example.com/static/app.js")
        self.assertIn("javascript", tags)

    def test_cache_buster_detection(self):
        self.assertTrue(is_cache_buster(["v"]))
        self.assertTrue(is_cache_buster(["_", "ts"]))
        self.assertFalse(is_cache_buster(["cat"]))
        self.assertFalse(is_cache_buster(["v", "cat"]))  # mixed → not pure cache-buster

    def test_injection_classes_routing(self):
        self.assertEqual(injection_classes(["cat"]), {"sqli"})
        self.assertIn("cmdi", injection_classes(["cmd"]))
        self.assertIn("xss", injection_classes(["search"]))
        self.assertEqual(injection_classes(["v"]), set())

    def test_scope_url_rejects_embedded_scheme_in_path(self):
        sc = Scope("vulnweb.com", include_subdomains=True, excludes=[])
        self.assertIsNone(sc.url("http://testphp.vulnweb.com/40http://testphp.vulnweb.com/AJAX/infoartist.php"))
        # a normal path is still accepted
        self.assertEqual(
            sc.url("http://testphp.vulnweb.com/listproducts.php?cat=1"),
            "http://testphp.vulnweb.com/listproducts.php?cat=1",
        )

    def test_dns_timeout_flag_default_and_validation(self):
        a = build_parser().parse_args(["example.com"])
        self.assertEqual(a.dns_timeout, 3)

    def test_sanitize_strips_foreign_payloads(self):
        from reconforge import sanitize_scan_url, looks_tainted
        self.assertTrue(looks_tainted("0+and+1=1--[True]"))
        self.assertTrue(looks_tainted("<script>alert(1)</script>"))
        self.assertFalse(looks_tainted("5"))
        self.assertFalse(looks_tainted("hello"))
        self.assertEqual(
            sanitize_scan_url("http://t.vulnweb.com/showforum.asp?id=0+and+1=1--%5BTrue%5D"),
            "http://t.vulnweb.com/showforum.asp?id=1",
        )
        self.assertEqual(
            sanitize_scan_url("http://t.vulnweb.com/s.asp?q=%3Cscript%3E"),
            "http://t.vulnweb.com/s.asp?q=test",
        )
        # a clean value is left untouched
        self.assertEqual(
            sanitize_scan_url("http://t.vulnweb.com/p.asp?id=5"),
            "http://t.vulnweb.com/p.asp?id=5",
        )

    def test_planner_dedups_endpoint_variants(self):
        # id=0, id=1, id=0+and+1=1--[True] must collapse to ONE clean scan target.
        import shutil
        td = tempfile.mkdtemp()
        try:
            recon = Recon(build_parser().parse_args(["vulnweb.com", "--subdomains", "--out", td]))
            for v in ("0", "1", "2", "0+and+1=1--%5BTrue%5D"):
                u = f"http://testasp.vulnweb.com/showforum.asp?id={v}"
                recon.store.url(u, "gau", probe=True)
                recon.store.finish(u, {"status": 200})
            recon.store.commit()
            asyncio.run(recon.plan_scans())
            lines = [l for l in (Path(td) / "scan_plan.json").read_text().splitlines() if l.strip()]
            self.assertEqual(len(lines), 1)                 # 4 variants collapsed to 1
            self.assertIn("showforum.asp?id=", lines[0])
            self.assertNotIn("and", lines[0].lower())       # foreign payload stripped
            self.assertNotIn("true", lines[0].lower())
            recon.store.conn.close()
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_active_features_list(self):
        from reconforge import _active_features
        a = build_parser().parse_args([
            "example.com", "--katana", "--bypass-403", "--auto-scan",
            "--identity", "A:Authorization: Bearer tok",
            "--scanners", "sqlmap", "dalfox",
        ])
        feats = _active_features(a)
        self.assertIn("katana", feats)
        self.assertIn("403-bypass", feats)
        self.assertIn("auto-scan", feats)
        self.assertIn("BOLA", feats)
        self.assertIn("scanners:sqlmap+dalfox", feats)

    def test_print_banner_and_summary_render_cleanly(self):
        from reconforge import print_banner, print_summary
        a = build_parser().parse_args(["example.com", "--subdomains"])
        print_banner(a)
        sample_summary = {
            "scope": "example.com",
            "subdomains_in_scope": 5,
            "urls_in_scope": 42,
            "alive_urls": 20,
            "http_probes_run": 30,
            "pending_urls": 12,
            "http_requests_builtin": 35,
            "manual_review_only": 2,
            "takeover_candidates": 1,
            "bypass_403_candidates": 0,
            "bola_candidates": 2,
            "secret_indicators_unverified": 3,
            "scan_plan_endpoints": 4,
        }
        print_summary(sample_summary, Path("."))

    def test_print_tools_table_renders_cleanly(self):
        from reconforge import check_system_tools, print_tools_table
        report = check_system_tools()
        print_tools_table(report)

    def test_rich_ui_helpers_render_cleanly(self):
        from reconforge import print_phase, print_scan_plan, print_findings_details
        print_phase("Fase 1", "Descoberta Passiva")
        sample_plan = [
            {
                "url": "https://api.example.com/v1/items?id=1",
                "classes": ["sqli", "xss"],
                "params": ["id"],
                "suggested_tools": ["sqlmap", "dalfox"],
            }
        ]
        print_scan_plan(sample_plan)
        print_findings_details(
            takeovers=[{"host": "old.example.com", "service": "GitHub Pages", "cname": "x.github.io"}],
            bypasses=[{"url": "https://example.com/admin", "technique": "header:X-Original-URL", "status": 200}],
            bolas=[{"url": "https://api.example.com/v1/user/1", "verdict": "likely_bola", "status_a": 200, "status_b": 200}],
            top_urls=[(95, 200, "api,admin", "katana", "https://api.example.com/admin/v1/users")],
        )

    def test_visual_dashboard_and_js_intel(self):
        import shutil
        td = tempfile.mkdtemp()
        try:
            a = build_parser().parse_args(["example.com", "--subdomains", "--visual", "--out", td])
            recon = Recon(a)
            recon.analyze_js(
                "https://example.com/static/app.js",
                'fetch("/api/v2/users?id=1"); const u = "https://api.example.com/v1/GraphQL"; //# sourceMappingURL=app.js.map',
            )
            st = recon.dashboard_state()
            self.assertEqual(st["js_count"], 1)
            self.assertTrue(st["js_intel"][0]["sourcemap"])
            self.assertIn("/api/v2/users?id=1", st["js_intel"][0]["routes"])
            recon.export()
            self.assertTrue((Path(td) / "dashboard.html").exists())
            asyncio.run(recon.aclose())
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_full_preset_enables_all_modules_and_default_out(self):
        from reconforge import _active_features
        p = build_parser()
        a = p.parse_args(["example.com", "--full"])
        apply_full_preset(a, ["example.com", "--full"])
        self.assertTrue(a.subdomains)
        self.assertTrue(a.katana)
        self.assertTrue(a.jsluice)
        self.assertTrue(a.gitleaks)
        self.assertTrue(a.trufflehog)
        self.assertTrue(a.fuzz)
        self.assertTrue(a.ffuf)
        self.assertTrue(a.takeover)
        self.assertTrue(a.bypass_403)
        self.assertEqual(a.scan_profile, "deep")
        self.assertEqual(a.out, str(Path("runs") / "example.com"))
        feats = _active_features(a)
        self.assertIn("FULL-PRESET", feats)

    def test_full_preserves_explicit_limits_profile_and_exact_host(self):
        argv = ["example.com", "--full", "--no-subdomains", "--no-takeover", "--scan-profile=safe",
                "--max-probes", "4000", "--max-requests=6000", "--out", "reconforge-output"]
        a = build_parser().parse_args(argv)
        apply_full_preset(a, argv)
        self.assertFalse(a.subdomains)
        self.assertFalse(a.takeover)
        self.assertEqual(a.scan_profile, "safe")
        self.assertEqual(a.max_probes, 4000)
        self.assertEqual(a.max_requests, 6000)
        self.assertEqual(a.out, "reconforge-output")


if __name__ == "__main__":
    unittest.main()
