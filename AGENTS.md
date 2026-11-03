# AGENTS.md — Instructions for any LLM/agent working on ReconForge

Read this fully before editing. These rules are mandatory.

## What this project is
`reconforge.py` is a single-file, scoped, resumable bug-bounty reconnaissance
engine (Python 3.14, `asyncio` + `httpx` + `sqlite3`). It discovers subdomains
and URLs, probes them, extracts endpoints/secrets, and routes an arsenal of
external scanners at injection candidates. It is meant for **large, authorized
scopes** (wildcard bug-bounty programs).

## Golden rules (do not break)
1. **Authorized use only.** The tool is for programs/targets the operator is
   authorized to test. Keep the scope guards intact (IDNA host norm, in-scope
   checks, DNS pinned to a validated public IP, private-IP rejection).
2. **Built-in collector is GET-only.** The Python probe/crawler never issues
   state-changing verbs. POST forms go to manual-review output, not auto-fetch.
   External scanners are the only active-exploitation layer and are opt-in
   (`--auto-scan` / `--scanners`).
3. **No AI attribution in commits/PRs.** Never add `Co-Authored-By: Claude`,
   "Generated with …", or any AI/agent mention. Commit messages are technical
   only. (Standing instruction from the repo owner.)
4. **Respect per-program rules.** Some programs ban enumeration and cap req/s
   (e.g. 5/s). Volume is lifted by default (`--unlimited`/`--full`), but the
   operator controls politeness via `--rate` / `--concurrency`. Never hardcode
   behavior that would violate a program's stated limits.
5. **Never commit internal/scratch files.** `HANDOFF.md`, `ANALISE_*.md`,
   `RELATORIO_*.md`, `NOTES_*`, lab-only scripts are git-ignored. Keep it so.
6. **Run the tests before every commit:** `python -m unittest discover -s tests -p "test_*.py"`.
   Keep them green. Add a regression test for every bug you fix.

## Design invariants
- **No volume caps in spirit.** The real throttle is rate/concurrency, not a
  hard stop mid-recon. `--unlimited` (and `0` on any single cap) → `INF_CAP`.
  `--full` implies unlimited + auto-scan + nuclei high-signal tags. Don't
  reintroduce low default ceilings that prune obscure subdomains/URLs.
- **Planner = every live parameterized endpoint is an injection candidate.**
  A matching param name (`INJECTION_ROUTES`) is a *priority hint*, not a gate.
  Only pure cache-buster params (`CACHE_BUSTER_PARAMS` / `is_versioned_asset`)
  are skipped. Candidates are deduped by (scheme, netloc, path, param-names)
  and payload-sanitized (`sanitize_scan_url`).
- **Arsenal per injection point:** `DEFAULT_ARSENAL = (sqlmap, dalfox, commix)`
  — one active tester per vuln class (SQLi/XSS/CMDi), all fired on each
  candidate. `ghauri` duplicates sqlmap → opt-in only via `--scan-tools`.
- **Scanners run via `stream_command`:** `stdin=DEVNULL` (never hang on
  prompts), native stdout streamed live tagged `[tool→host]` and saved to
  `runs/<out>/tools/*.stdout`. Parallelism bounded by `--scan-concurrency`.
  Keep commix non-destructive (`--technique=rbt`, no file writes to target).
- **Resilience:** every pipeline phase is wrapped (`Recon._safe`) so one
  failing phase/tool never aborts the run — export always runs.
- **Resume is cumulative:** request/probe budget persists in the `meta` table;
  a resume honors the ceiling instead of restarting it.
- **Rich UI optional:** `rich` drives banner/logs/summary; degrade cleanly to
  plain logging when absent or non-TTY (files/pipes stay greppable).

## The one command
`python reconforge.py <domain> --full` — turnkey: unlimited discovery, all
discovery+JS+secret+takeover+403 modules, arsenal auto-scan, nuclei high-signal
tags, output to `runs/<domain>/`. Tune politeness with `--rate`/`--concurrency`.

## Where things live (reconforge.py)
- Scope/normalization: `hostnorm`, `Scope`, `PinnedTransport` (DNS-pinned transport with IP cache).
- Scoring/routing: `score`, `INJECTION_ROUTES`, `classify_url`, `sanitize_scan_url`.
- Pipeline: `Recon._run_locked` (phase order), `probe`, `drain`, `crawl_katana`,
  `browser`, `wordlist_fuzz`, `ffuf`, `takeover`, `bypass_403`, `bola`,
  `offline_secrets`, `scanners`, `plan_scans`, `_run_plan`.
- Exec: `command` / `stream_command` (+ `tool_process_argv` for Windows .bat shims).
- CLI/presets: `build_parser`, `apply_full_preset`, `main`.

## Workflow for the next agent
1. Read `HANDOFF.md` (git-ignored, repo root) for current state and TODO.
2. Make changes; add/adjust tests; run the suite.
3. Update `HANDOFF.md` with what you did and what remains.
4. Commit (no AI attribution). Prefer a feature branch over the default branch.
