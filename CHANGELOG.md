# Changelog

Semantic versioning; pre-1.0 minors carry breaking changes.

## v0.2.0 — 2026-08-20 — BREAKING

### Breaking
- **`--execute` is gone; `--yes` is the single write gate.** Bare
  `apply` / `destroy NAME` is a dry run; `--yes` confirms (preview
  table prints first, then writes). `apply --execute` now fails at
  parse time (exit 2) with guidance to use `apply --yes`. Scripts and
  aliases must switch.
- **Interactive confirmations removed** (no typed-`yes` prompt, no
  typed-group-name prompt for destroy). Automation that fed stdin
  expecting the prompt gets no prompt and no write — it must pass
  `--yes`.
- **Rate exhaustion now waits and retries** (planning reads included)
  instead of fast-failing with `throttled` statuses and rc 1: an
  unattended run may block up to one 5-min window per exhaustion
  (bounded retries, Ctrl+C aborts). CI expecting rc-1-on-throttle will
  now see rc 0 after the wait.
- **`plan`/`apply`/`destroy` auto-use `snapshot.json`** when the file
  exists in the project directory (offline planning, stderr notice).
  Delete the file or pass `--snapshot` to control the source explicitly.

### Added
- `hcs-sg snapshot`: whole-cloud inventory export in 2 paged calls
  (SGs with embedded rules + all ports); `--out` path option.
- `hcs-sg drift [--json]`: live cloud vs snapshot; keyed by cloud IDs
  (duplicate names safe); `--json` emits the Liquibase diff shape
  (`missing/unexpected/changedObjects` with per-field
  `referenceValue`/`comparedValue`); rc 1 on drift.
- `--verbose`: stderr progress log (gateway calls with budget, plan
  phases, per-action results); stdout stays pure under `--json`.
- Cloud self-referential rules (HCS auto-adds allow-within-SG) are
  preserved — never converged away, matched by coded self-references.
- Duplicate cloud SG names enumerate every name and id.
- Unretryable cloud failures print one clean `error: …` line (never a
  traceback); QuotaExhausted/CloudThrottled carry the window deadline
  and the recent-call trail (the exact sequence that hit the 429).
- `SSL_VERIFY=false` mutes urllib3 InsecureRequestWarning.
- Preview table always precedes writes; clear-all WARNING rendered in
  the plan (visible in dry runs too).

## v0.1.0 — 2026-08-20
- Initial import: `validate`/`plan`/`apply`/`destroy`/`schema`, dry-run
  by default, frame-catalogue test suite (3 tier-routed consumers +
  coverage guard), AST-enforced clean-architecture rings, fixed-window
  rate limiter with adaptive backoff, audit JSONL, in-memory fake
  gateway + gated real-cloud contract suite.
- Write-path wait-and-continue on rate exhaustion;
  InsecureRequestWarning muted under `SSL_VERIFY=false`.
