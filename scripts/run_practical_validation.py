"""Reproducible, bounded validation for the two explicitly authorized scopes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'runs' / 'practical-2026-11-02'
TARGETS = ['seidorcloud.com.br', 'b1cloud.com.br']


def main():
    RUN.mkdir(parents=True, exist_ok=True)
    template = RUN / 'technology-check.yaml'
    template.write_text('''id: reconforge-technology-check
info:
  name: Bounded root technology inventory
  author: reconforge-local-validation
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    redirects: false
    matchers:
      - type: status
        status: [200, 301, 302, 401, 403]
    extractors:
      - type: kval
        kval: [server, x_powered_by]
''', encoding='utf8')
    manifest = []
    env = {**os.environ, 'PYTHONUNBUFFERED': '1', 'PYTHONUTF8': '1'}
    for target in TARGETS:
        out = RUN / target
        command = [sys.executable, '-u', str(ROOT / 'reconforge.py'), target,
                   '--full', '--scan-profile', 'safe', '--browser', '--auto-scan', '--amass',
                   '--scanners', 'nuclei', '--nuclei-templates', str(template),
                   '--rate', '2', '--concurrency', '2', '--dns-concurrency', '5',
                   '--max-hosts', '20', '--max-urls', '2000', '--max-import-lines', '5000',
                   '--max-probes', '100', '--initial-probes', '40', '--max-requests', '200',
                   '--max-crawl-hosts', '3', '--max-ffuf-hosts', '2', '--max-fuzz-words', '14',
                   '--crawl-depth', '2', '--max-pages', '2', '--bypass-limit', '2',
                   '--scan-limit', '3', '--scan-plan-limit', '2', '--timeout', '6',
                   '--tool-timeout', '45', '--no-auto-install', '--out', str(out)]
        entry = {'target': target, 'command': command, 'started': time.time(), 'state': 'running'}
        manifest.append(entry)
        (RUN / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
        print('\nSTART ' + target + '\n' + subprocess.list2cmdline(command), flush=True)
        with (RUN / (target + '.log')).open('w', encoding='utf8') as log:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding='utf8', errors='replace')
            entry['pid'] = process.pid
            (RUN / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
            try:
                for line in process.stdout:
                    print(line, end='', flush=True)
                    log.write(line)
                    log.flush()
                entry['exit_code'] = process.wait()
                entry['state'] = 'finished' if entry['exit_code'] == 0 else 'failed'
            except KeyboardInterrupt:
                entry['state'] = 'interrupted'
                raise
            finally:
                entry['ended'] = time.time()
                (RUN / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf8')
        print('END ' + target + ' ' + entry['state'], flush=True)


if __name__ == '__main__':
    main()
