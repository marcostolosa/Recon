"""Exercise post-run fixes only against the loopback Juice Shop lab."""
import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import reconforge as rf


async def main():
    rf.ensure_tool_paths()
    a = rf.build_parser().parse_args([
        '127.0.0.1', '--allow-private', '--scan-profile', 'safe', '--rate', '5',
        '--concurrency', '2', '--timeout', '5', '--tool-timeout', '30',
        '--bypass-403', '--bypass-limit', '1', '--no-auto-install',
        '--out', str(ROOT / 'runs/practical-2026-11-02/juice-shop-corrected'),
    ])
    r = rf.Recon(a)
    try:
        with rf.RunLock(r.out / '.run.lock'):
            for url in ['http://127.0.0.1/', 'http://127.0.0.1/rest/user/change-password?current=']:
                r.put_url(url, 'validation')
                await r.probe(url)
            await r.bypass_403()
            print('Corrected bypass candidates:', len(r.bypass_hits), flush=True)
            assert not r.bypass_hits, r.bypass_hits
            await r.command('commix_after_dependency', r._scan_argv(
                'commix', 'http://127.0.0.1/rest/products/search?q=apple', r.out / 'scanners'))
            r.export()
    finally:
        await r.aclose()


if __name__ == '__main__':
    asyncio.run(main())
