"""Security regressions use synthetic credentials and in-memory HTTP responses."""
import asyncio
from contextlib import closing
import json
import hashlib
from pathlib import Path
import socket
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from reconforge import PinnedTransport, Recon, RunLock, Scope, Store, build_parser


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.args = build_parser().parse_args([
            'example.com', '--out', self.temp.name, '--subdomains',
            '-H', 'Authorization: Bearer FAKE_DISCOVERY_TOKEN',
            '-H', 'X-Bug-Bounty: audit', '--exclude-path', '/blocked',
            '--identity', 'A:Authorization: Bearer FAKE_A',
            '--identity', 'B:Authorization: Bearer FAKE_B',
        ])
        self.r = Recon(self.args)
        self.addAsyncCleanup(self.r.aclose)
        await self.r.client.aclose()
        await self.r.passive_client.aclose()
        self.seen = []
        self.responses = {}

        def handler(req):
            self.seen.append(req)
            response = self.responses.get(req.url.path)
            if callable(response):
                return response(req)
            return response or httpx.Response(200, text='default')

        self.handler = handler
        self.r.make_client = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
        self.r.client = self.r.make_client()
        self.r.passive_client = self.r.make_client()
        self.r.resolves = AsyncMock(return_value=True)
        self.r.gate.rate = 100000

    def seed(self, url, status=200, **data):
        self.r.put_url(url, 'audit')
        self.r.store.finish(url, {'status': status, **data})

    async def test_ct_does_not_receive_target_headers(self):
        self.responses['/'] = httpx.Response(200, json=[])
        await self.r.ct_provider('crtsh', 'https://crt.sh/', {})
        request = self.seen[-1]
        self.assertNotIn('authorization', request.headers)
        self.assertNotIn('cookie', request.headers)
        self.assertNotIn('x-bug-bounty', request.headers)

    async def test_headers_bound_to_explicit_https_hosts(self):
        self.assertIn('authorization', self.r.headers_for('https://example.com/'))
        self.assertNotIn('authorization', self.r.headers_for('https://api.example.com/'))
        self.assertNotIn('authorization', self.r.headers_for('http://example.com/'))
        self.r.credential_hosts.add('api.example.com')
        self.assertIn('authorization', self.r.headers_for('https://api.example.com/'))

    async def test_discovery_cookie_jars_are_separate_per_origin(self):
        self.responses['/set'] = httpx.Response(200, headers={'set-cookie': 'session=A; Domain=example.com; Path=/'})
        await self.r.raw_get('https://example.com/set')
        await self.r.raw_get('https://api.example.com/check')
        self.assertNotIn('cookie', self.seen[-1].headers)

    async def test_policy_blocks_raw_requests_before_transport(self):
        for url in ['https://outside.invalid/', 'https://example.com/blocked',
                    'https://example.com/%62locked', 'https://example.com/a/../blocked',
                    'https://example.com/%2562locked', 'https://example.com/%6cogout',
                    'https://example.com/a/%2e%2e/blocked']:
            with self.subTest(url=url):
                self.assertIsNone(await self.r.raw_get(url))
        self.assertEqual(self.seen, [])
        self.assertEqual(self.r.gate.count, 0)

    async def test_probe_rechecks_policy_for_old_queue_entries(self):
        self.r.store.url('https://example.com/blocked', 'old')
        await self.r.probe('https://example.com/blocked')
        self.assertFalse(self.seen)

    async def test_identity_and_anon_sessions_are_isolated(self):
        self.seed('https://example.com/api/account')
        self.r.client.cookies.set('session', 'DISCOVERY', domain='example.com')

        def response(req):
            token = req.headers.get('authorization', '')
            cookie = 'ACCOUNT_A' if token.endswith('FAKE_A') else 'OTHER'
            return httpx.Response(200, text=token or 'anonymous', headers={'set-cookie': f'session={cookie}; Path=/'})

        self.responses['/api/account'] = response
        await self.r.bola()
        self.assertEqual(len(self.seen), 3)
        self.assertNotIn('authorization', self.seen[0].headers)
        self.assertNotIn('cookie', self.seen[0].headers)
        self.assertEqual(self.seen[1].headers['authorization'], 'Bearer FAKE_A')
        self.assertEqual(self.seen[2].headers['authorization'], 'Bearer FAKE_B')
        self.assertNotIn('cookie', self.seen[2].headers)
        self.assertFalse(self.r.bola_findings)

    async def test_equal_length_bodies_are_not_identical(self):
        self.seed('https://example.com/api/account')
        self.responses['/api/account'] = lambda req: httpx.Response(
            200, text='AAAA' if req.headers.get('authorization', '').endswith('FAKE_A') else
            'BBBB' if req.headers.get('authorization', '').endswith('FAKE_B') else 'CCCC')
        await self.r.bola()
        self.assertFalse(self.r.bola_findings)

    async def test_identical_resource_is_candidate_with_evidence(self):
        self.seed('https://example.com/api/account')
        # Genuinely gated: anonymous is forbidden, so the identical body that accounts
        # A and B both receive is NOT public — that is the real cross-account signal.
        self.responses['/api/account'] = lambda req: (
            httpx.Response(200, text='same protected resource')
            if req.headers.get('authorization') else httpx.Response(401, text='login required'))
        await self.r.bola()
        self.assertTrue(any(f['type'] == 'cross_identity_identical' for f in self.r.bola_findings))
        self.assertGreater(self.r.store.conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0], 0)

    async def test_public_page_identical_for_all_is_not_a_finding(self):
        # Regression for the false positive: if anon sees the SAME body as A and B,
        # the resource is public and must NOT be flagged as a BOLA candidate.
        self.seed('https://example.com/about')
        self.responses['/about'] = httpx.Response(200, text='public about page')
        await self.r.bola()
        self.assertFalse(self.r.bola_findings)

    async def test_redirects_are_not_authz_success(self):
        self.seed('https://example.com/api/account')
        self.responses['/api/account'] = httpx.Response(302, headers={'location': '/login'})
        await self.r.bola()
        self.assertFalse(self.r.bola_findings)

    async def test_budget_is_durable_before_http_send(self):
        def response(req):
            with closing(sqlite3.connect(Path(self.temp.name) / 'state.sqlite')) as conn:
                count = conn.execute("SELECT value FROM meta WHERE key='requests_total'").fetchone()[0]
            self.assertEqual(int(count), 1)
            return httpx.Response(200, text='ok')
        self.responses['/check'] = response
        await self.r.raw_get('https://example.com/check')
        self.assertEqual(self.r.store.get_int('requests_total'), 1)

    async def test_request_budget_stops_all_internal_fetches(self):
        self.r.gate.cap = 1
        await self.r.raw_get('https://example.com/check')
        self.assertIsNone(await self.r.raw_get('https://example.com/check2'))
        self.assertEqual(len(self.seen), 1)

    async def test_probe_budget_is_persisted_before_response(self):
        self.seed('https://example.com/check')
        await self.r.probe('https://example.com/check')
        self.assertEqual(self.r.store.get_int('probes_total'), 1)

    async def test_browser_aborts_exclusions_redirects_and_large_bodies(self):
        def route(url):
            return SimpleNamespace(request=SimpleNamespace(url=url, method='GET', resource_type='document'),
                                   abort=AsyncMock(), fulfill=AsyncMock())
        blocked = route('https://example.com/blocked')
        await self.r.browser_route(blocked)
        blocked.abort.assert_awaited_once()
        self.assertFalse(self.seen)
        self.responses['/redirect'] = httpx.Response(302, headers={'location': 'https://outside.invalid/'})
        redirect = route('https://example.com/redirect')
        await self.r.browser_route(redirect)
        redirect.abort.assert_awaited_once()
        redirect.fulfill.assert_not_awaited()
        self.assertEqual(len(self.seen), 1)
        self.r.a.max_body = 4
        large = route('https://example.com/large')
        await self.r.browser_route(large)
        large.abort.assert_awaited_once()

    async def test_browser_fulfills_from_bounded_internal_transport(self):
        route = SimpleNamespace(request=SimpleNamespace(url='https://example.com/ok', method='GET', resource_type='document'),
                                abort=AsyncMock(), fulfill=AsyncMock())
        await self.r.browser_route(route)
        route.fulfill.assert_awaited_once()
        self.assertEqual(self.seen[-1].headers['authorization'], 'Bearer FAKE_DISCOVERY_TOKEN')

    async def test_url_limit_is_hard_and_manual_entries_stay_manual(self):
        store = Store(Path(self.temp.name) / 'small.sqlite', 1)
        try:
            self.assertTrue(store.url('https://example.com/a', 'html', probe=False))
            self.assertFalse(store.url('https://example.com/b', 'html'))
            store.url('https://example.com/a', 'js_call', probe=True)
            self.assertFalse(store.pending(10))
            self.assertEqual(store.count('urls'), 1)
        finally:
            store.conn.close()

    async def test_scope_mismatch_does_not_overwrite_existing_artifacts(self):
        config = Path(self.temp.name) / 'run_config.json'
        config.write_text(json.dumps(self.r.scope_config()), encoding='utf8')
        summary = Path(self.temp.name) / 'summary.json'
        summary.write_text('original', encoding='utf8')
        args = build_parser().parse_args(['other.invalid', '--out', self.temp.name])
        with self.assertRaises(ValueError):
            Recon(args)
        self.assertEqual(summary.read_text(), 'original')

    async def test_output_directory_has_exclusive_execution_lock(self):
        path = Path(self.temp.name) / '.run.lock'
        with RunLock(path):
            with self.assertRaises(ValueError):
                with RunLock(path):
                    self.fail('concurrent run acquired lock')
        with RunLock(path):
            pass

    async def test_scanner_headers_threads_and_secret_free_script(self):
        self.r.a.exclude_path = []
        url = 'https://example.com/?id=1'
        for tool in ['sqlmap', 'ghauri', 'commix', 'dalfox']:
            argv = self.r._scan_argv(tool, url, Path(self.temp.name))
            self.assertIn('Bearer FAKE_DISCOVERY_TOKEN', '\n'.join(argv))
            self.assertNotIn('--random-agent', argv)
            self.assertNotIn('FAKE_DISCOVERY_TOKEN', self.r.shell_command(argv))
        self.r._write_scan_script([], {'sqlmap': [url]}, Path(self.temp.name))
        text = (Path(self.temp.name) / 'scan_plan.sh').read_text(encoding='utf8')
        self.assertIn('RECONFORGE_SECRET_', text)
        self.assertNotIn('FAKE_DISCOVERY_TOKEN', text)

    async def test_planner_clears_stale_plan_and_counts_routed_urls(self):
        plan = Path(self.temp.name) / 'scan_plan.json'
        plan.write_text('stale')
        # Pure cache-buster param -> no real input surface -> no candidate (stale cleared).
        self.seed('https://example.com/?v=123')
        await self.r.plan_scans()
        self.assertEqual(plan.read_text(), '')
        self.assertEqual(self.r.scan_plan_count, 0)
        # Any genuine parameterized endpoint is now a candidate (name is a hint, not a gate).
        self.seed('https://example.com/?id=1')
        await self.r.plan_scans()
        self.assertEqual(self.r.scan_plan_count, 1)

    async def test_planner_preserves_distinct_origins(self):
        self.seed('https://example.com/item?id=1')
        self.seed('https://api.example.com/item?id=1')
        self.seed('http://example.com/item?id=1')
        await self.r.plan_scans()
        self.assertEqual(self.r.scan_plan_count, 3)

    async def test_planner_does_not_scan_static_build_ids(self):
        self.seed('https://example.com/livewire/livewire.js?id=df3a17f2')
        self.seed('https://example.com/api/item?id=df3a17f2')
        await self.r.plan_scans()
        self.assertEqual(self.r.scan_plan_count, 1)
        self.assertIn('/api/item?', self.r.plan_items[0]['url'])

    async def test_openapi_non_get_operations_remain_manual(self):
        payload = json.dumps({'paths': {'/submit': {'post': {}}, '/fetch': {'get': {}}}}).encode()
        self.r.extract('https://example.com/openapi.json', 'application/json', payload)
        self.r.put_url('https://example.com/submit', 'html')
        self.assertEqual(self.r.store.pending(10), ['https://example.com/fetch'])

    async def test_findings_survive_resume_and_export_empty_files(self):
        self.r.add_finding('bypass', {'url': 'https://example.com/a', 'status': 200})
        self.r.bypass_hits.clear()
        self.r.export()
        self.assertEqual(len(self.r.bypass_hits), 1)
        self.assertEqual((Path(self.temp.name) / 'bola_candidates.jsonl').read_text(), '')

    async def test_soft404_calibration_survives_resume(self):
        self.r.soft404 = {'https://example.com/': {'status': 200, 'body_hash': 'baseline', 'bytes': 100}}
        self.r.export()
        resumed = Recon(self.args)
        try:
            self.assertEqual(resumed.soft404, self.r.soft404)
        finally:
            await resumed.aclose()

    async def test_query_representation_is_preserved(self):
        url = 'https://example.com/?x=2&x=1&encoded=%2f&space=%20'
        self.assertEqual(Scope('example.com', False, []).url(url), url)

    async def test_integer_delay_scanner_contracts(self):
        self.r.a.rate = 5
        self.r.a.exclude_path = []
        for tool in ('commix', 'ghauri'):
            argv = self.r._scan_argv(tool, 'https://example.com/?q=test', Path(self.temp.name))
            self.assertEqual(argv[argv.index('--delay') + 1], '1')

    async def test_html_fallback_is_not_parsed_as_javascript(self):
        payload = b'<!doctype html><html><script src="fake.js"></script></html>'
        self.r.extract('https://example.com/missing.js', 'text/html', payload)
        self.r.extract('https://example.com/missing.mjs', 'application/javascript', payload)
        self.assertFalse(self.r.js_saved)
        self.assertFalse(self.r.store.pending(10))

    async def test_dashboard_state_cannot_close_script_element(self):
        self.seed('https://example.com/</script><script>alert(1)</script>')
        self.r.export()
        html = (Path(self.temp.name) / 'dashboard.html').read_text(encoding='utf8')
        self.assertNotIn('</script><script>alert(1)</script>', html)
        self.assertIn('\\u003c/script\\u003e', html)

    async def test_ffuf_filters_words_before_external_execution(self):
        self.r.a.ffuf = True
        self.seed('https://example.com/')
        wordlist = Path(self.temp.name) / 'words.txt'
        wordlist.write_text('blocked\nlogout\n%62locked\nvalid\n', encoding='utf8')
        self.r.a.wordlist = str(wordlist)
        async def command(name, argv):
            words = Path(argv[argv.index('-w') + 1]).read_text(encoding='utf8').splitlines()
            self.assertEqual(words, ['valid'])
            self.assertIn('authorization: Bearer FAKE_DISCOVERY_TOKEN', argv)
            return None
        self.r.command = AsyncMock(side_effect=command)
        await self.r.ffuf()
        self.r.command.assert_awaited_once()

    async def test_external_tools_do_not_run_when_exclusions_cannot_be_enforced(self):
        self.r.a.katana = True
        self.r.a.scanners = ['sqlmap']
        self.r.command = AsyncMock()
        await self.r.crawl_katana()
        await self.r.scanners()
        await self.r._run_plan({'sqlmap': ['https://example.com/?id=1']}, Path(self.temp.name))
        self.r.command.assert_not_awaited()

    async def test_bypass_redirect_is_not_reported_and_partial_results_are_durable(self):
        self.r.a.bypass_403 = True
        self.r.a.max_requests = 1
        self.r.gate.cap = 1
        self.seed('https://example.com/private', status=403, body_hash='forbidden')
        self.responses['/private'] = httpx.Response(302, headers={'location': '/login'})
        await self.r.bypass_403()
        self.assertFalse(self.r.bypass_hits)
        self.responses['/private'] = httpx.Response(200, text='possible protected response')
        self.r.gate.count = 0
        self.r.gate.cap = 1
        await self.r.bypass_403()
        self.r.export()
        content = (Path(self.temp.name) / 'bypass403_candidates.jsonl').read_text(encoding='utf8')
        self.assertIn('private', content)

    async def test_bypass_ignores_normal_homepage_responses(self):
        self.r.a.bypass_403 = True
        self.seed('https://example.com/', body_hash=hashlib.sha256(b'default').hexdigest())
        self.seed('https://example.com/private', status=403, body_hash='forbidden')
        self.responses['/private'] = httpx.Response(403, text='forbidden')
        await self.r.bypass_403()
        self.assertFalse(self.r.bypass_hits)

    async def test_changed_identity_override_order_invalidates_resume_context(self):
        self.r.a.identity = ['A:Authorization: FIRST', 'A:Authorization: LAST']
        before = self.r.scope_config()
        self.r.a.identity.reverse()
        self.assertNotEqual(before, self.r.scope_config())


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_pinned_transport_against_local_http_server(self):
        async def serve(reader, writer):
            try:
                data = await reader.readuntil(b'\r\n\r\n')
                self.assertIn(b'Host: example.com:', data)
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(serve, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        transport = PinnedTransport(allow_private=True, timeout=2, concurrency=1)
        resolver = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))])
        try:
            with patch.object(asyncio.get_running_loop(), 'getaddrinfo', resolver):
                async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
                    response = await client.get(f'http://example.com:{port}/')
                    self.assertEqual(response.text, 'ok')
        finally:
            server.close()
            await server.wait_closed()

    async def test_dns_pinning_keeps_host_and_sni(self):
        transport = PinnedTransport(allow_private=False, timeout=1, concurrency=1)
        self.addAsyncCleanup(transport.aclose)
        captured = []
        async def handle(req):
            captured.append(req)
            return httpx.Response(200, text='ok')
        transport.transports['example.com'] = httpx.MockTransport(handle)
        resolver = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))])
        with patch.object(asyncio.get_running_loop(), 'getaddrinfo', resolver):
            async with httpx.AsyncClient(transport=transport) as client:
                await client.get('https://example.com/path')
        self.assertEqual(captured[0].url.host, '93.184.216.34')
        self.assertEqual(captured[0].headers['host'], 'example.com')
        self.assertEqual(captured[0].extensions['sni_hostname'], 'example.com')

    async def test_private_dns_answer_never_reaches_transport(self):
        transport = PinnedTransport(allow_private=False, timeout=1, concurrency=1)
        self.addAsyncCleanup(transport.aclose)
        resolver = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))])
        with patch.object(asyncio.get_running_loop(), 'getaddrinfo', resolver):
            async with httpx.AsyncClient(transport=transport) as client:
                with self.assertRaises(httpx.ConnectError):
                    await client.get('https://example.com/')
        self.assertFalse(transport.transports)
