# hcs-sg-iac

Security-group-as-code for Huawei Cloud Stack 8.5.1. Groups first
(members = VM NIC IPs), then rules between groups (or CIDRs).
Dry run by default — `--yes` is the only path to real writes.

## Install

    python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

## Configure

    set -a; source .env; set +a      # see .env.example

## Usage

One rule covers every command: **nothing writes without `--yes`.** Bare
`apply`/`destroy` is a dry run (same output as `plan`); `--yes` confirms
it — the preview table prints first, then the writes. `plan` (and
`validate`/`schema`) reject `--yes` at parse time: read-only by
construction.

    hcs-sg validate                  # files only, no credentials
    hcs-sg plan                      # diff code vs cloud (read-only)
    hcs-sg apply                     # same dry run as plan
    hcs-sg apply --yes               # preview, then write (audited)
    hcs-sg destroy web-tier --yes    # preview, then delete
    hcs-sg plan --verbose            # progress log to stderr (works on
                                     # apply/destroy too; stdout stays pure)

## Project files

Per-SG directory layout (the default for new projects and `hcs-sg
import`): one directory per security group under `security-groups/` —
the directory name IS the group name, `group.yaml` describes it, and
each direction is its own file:

    security-groups/web-tier/
    ├── group.yaml               # name, description, members: [ip: ...]
    ├── ingress.yaml             # list of {source, protocol, ports}
    └── egress.yaml              # list of {destination, protocol, ports}

An absent `ingress.yaml`/`egress.yaml` = that direction is UNMANAGED;
`[]` in the file = managed remove-all. Environments conventionally live
as sibling subprojects: `hcs-sg plan --project projects/dev` (each with
its own groups/rules/snapshot/audit).

The legacy flat `groups/`+`rules/` layout was REMOVED in v0.6.0 —
running against an old project fails with a one-line hint to delete it
and re-`import` (offline, zero cloud calls).

`source`/`destination` = group name or CIDR (`0.0.0.0/0`, bare IPs
auto-/32). Protocol: tcp|udp|icmp|icmpv6|all. Ports: "80", "22,443",
"8000-9000" (max 20 entries after merging; unquoted ints and YAML lists
accepted). A missing `ingress:`/`egress:` section (or no rules file at
all) = unmanaged — the tool never touches those cloud rules and `plan`
lists them under NOT MANAGED; `[]` = remove all rules in that direction
(extra confirmation). File names must equal the group name. The
self-referential rules HCS adds automatically on SG create (allow
within the group) are preserved — never converged away, not even by a
`[]` direction; a coded self-reference (`source: <own group>`) matches
them instead of duplicating.

## Install as a CLI tool (pipx / uv)

`uv tool install` (uv's pipx) or `pipx install` give an isolated venv
and `hcs-sg` on PATH:

    uv tool install .                                        # local checkout
    uv tool install git+ssh://git@ssh.github.com:443/alex-tw-lam/hcs-sg-iac-v2.git
    pipx install "git+ssh://git@ssh.github.com:443/alex-tw-lam/hcs-sg-iac-v2.git"

(the SSH-over-443 URL works on networks where github.com HTTPS is
filtered; use `git+https://github.com/...` where it is not). Build
distributables with `uv build` → `dist/` (sdist + wheel), installable
via `uv tool install ./dist/hcs_sg_iac-*.whl` or
`pipx install ./dist/...`. Environment variables (HCS_*, see
Configure) are still required at runtime; upgrade with
`uv tool upgrade hcs-sg-iac` / `pipx upgrade hcs-sg-iac`.

## Snapshot & drift (offline pre-work)

Spend the rate budget ONCE on inventory, then plan as often as you like
with zero cloud calls (and no credentials):

    hcs-sg snapshot                          # whole cloud: 2 paged calls
                                            # (SGs w/ embedded rules +
                                            # all ports), writes
                                            # snapshot.json
    hcs-sg plan                              # snapshot.json present?
                                            # used automatically, offline
    hcs-sg apply --yes                       # plan offline, write live
    hcs-sg drift [--json]                    # live cloud vs the file;
                                            # rc 1 when anything drifted

The inventory fast path uses `GET /v2.0/security-groups` (each SG's
rules are embedded in the response) plus one unfiltered
`GET /v1/{project_id}/ports` (membership via port.security_groups, the
IP→NIC index via fixed_ips) — the whole estate in **2 paged calls**
instead of 1 + 2N; every SDK endpoint is cross-checked against the HCS
8.5.1 VPC API Reference. `--snapshot FILE` overrides the default
`snapshot.json`; delete the file to read live again. After a write run
the snapshot is deliberately NOT auto-updated (a snapshot is a
point-in-time artifact, not a hidden state file): the CLI notes the
staleness on stderr — refresh with `hcs-sg snapshot`, or verify what
actually landed with `hcs-sg drift` (keyed by cloud IDs, so duplicate
names never confuse it). `drift --json` emits a Liquibase-diff-shaped
result (`missingObjects` / `unexpectedObjects` / `changedObjects` with
per-field `referenceValue`/`comparedValue`).

## Reverse import (adopt the estate)

`NOT MANAGED` lines in a plan are cloud SGs with no config file. Adopt
them by generating `groups/` and `rules/` YAML **from the snapshot** —
offline, zero cloud calls:

    hcs-sg snapshot            # fresh inventory first (the import source)
    hcs-sg import              # writes security-groups/<name>/{group,ingress,egress}.yaml
                               # refuses to overwrite existing files
                               # without --force; --json lists what it did

Both directions of every imported group are fully managed: the next
`hcs-sg plan` reconciles the cloud to the files (delete a file to
unmanage again). Anything the v4 config model cannot represent exactly
is skipped **with a note, never silently**: names that cannot be file
names, duplicate cloud names (config keys groups by name — the first id
wins, and rules that referenced a loser by id are skipped too),
self-referential rules (implicit: the platform re-adds them and the
plan preserves them), IPv6 remotes and unknown protocols. A rule whose
remote is UNSET imports as an explicit 0.0.0.0/0 — the plan engine
already reads such cloud rules as "anywhere" (API default when unset),
so import agrees instead of planning a phantom delete. Note the
consequence spelled out in each note: a skipped RULE is no longer
wanted, so the next plan shows it as a stale delete — remove it in the
cloud first if you want to keep it. The property is pinned by test:
import → write → load → plan converges with zero actions on a
representable cloud.

`import` adopts EVERYTHING representable — including SGs whose rules a
platform controller (CCE, GaussDB, …) edits on its own. Managing those
means every controller change becomes drift and the next `apply` would
revert it; keep such groups out deliberately (delete their files — a
group without a file is simply unmanaged).

## Logging

One voice, three verbs, two streams — the same shape on the fake
(tests) and the real gateway:

- **`phase: <what>`** — command progress (`phase: reading cloud
  snapshot`, `phase: importing from snapshot.json`, ...). Every command
  emits at least one.
- **`gateway call <method> (<used>/<limit> this window, <ms> ms)`** —
  one line per cloud call, emitted by BOTH gateways with the same
  template (the fake reports `0 ms` / `unlimited` where it cannot know).
- **`action <status>: <sign> <type> <group>`** — per write result.

Levels: `INFO` for progress; `WARNING` for throttles, near-exhausted
budget and failed/throttled actions. Streams: stdout carries command
results only (pure JSON under `--json`); everything else — logs,
wait-and-continue notices, staleness notes — goes to stderr with the
`hcs-sg: ` prefix. Logs appear with `--verbose` (a stderr handler on
the `hcs_sg_iac` logger tree); the wait notices and notes print always,
so an unattended run is never silent about why it is blocked.

## JSON Schema

Editor/validation schemas for the config files, generated from the model
(single source of truth — patterns and enums come from the model
constants, a drift guard test pins the committed copies):

    hcs-sg schema group           # group.yaml schema
    hcs-sg schema ingress         # ingress.yaml schema (egress alike)
    hcs-sg schema                 # both, keyed

Static copies live in `schemas/*.schema.json` (JSON Schema draft
2020-12); a drift-guard test pins them to a fresh export. Regenerate
after model changes:

    hcs-sg schema group > schemas/group-file.schema.json
    hcs-sg schema ingress > schemas/ingress-file.schema.json
    hcs-sg schema egress > schemas/egress-file.schema.json

Single-file constraints only — filename==name, cross-file
group refs and cloud-side IP resolution are validated by `hcs-sg
validate`/`plan`, not expressible in a per-file schema.

## Safety

- No state file: groups match cloud security groups by name; the member
  IP list is the truth (attached-but-unlisted NICs are detached).
- Cloud rules are immutable: edits are delete + create, shown honestly.
- Rule edits create before delete (no transient coverage gap).
- Rate-limit first: shared cloud quota is 90 calls / 5 min; this tool's
  slice defaults to 25 per window (SERVICE_CALL_BUDGET — planning reads
  spend it too, so size it to your estate). Exhausted or
  cloud-throttled (429): the run waits out the window (notice on stderr)
  and retries — planning reads included — continuing across windows
  instead of stopping; Ctrl+C aborts. If the gateway can't report a
  retry deadline, remaining actions are marked throttled and re-running
  `apply` resumes (idempotent). Unretryable cloud failures print one
  clean `error: …` line (never a traceback).
- `SSL_VERIFY=false` also mutes the noisy Unverified-HTTPS warnings
  (you already opted out; the tool won't nag about it on every call).
- Every `--yes` run appends a record to `audit.jsonl` in the
  project directory (timestamp, actions, created cloud ids, quota).
- Whole-group deletion only via explicit `destroy` (typed-name
  confirmation). Removing a file just unmanages the group.

## Lint, format, types

Four gates, all configured in pyproject.toml (black line-length 79 —
the house style; ruff replaces flake8+isort+pyupgrade; mypy checks the
prod ring only):

    .venv/bin/python -m black .            # format
    .venv/bin/python -m ruff check .       # lint (E/W/F/I/UP/B/SIM/C4/RUF)
    .venv/bin/python -m mypy               # types (hcs_sg_iac only)
    .venv/bin/python -m pytest -q          # behaviour

`pre-commit` wiring lives in .pre-commit-config.yaml, but it clones hook
envs over HTTPS — on the air-gapped RHEL box run the four commands above
instead.

## Tests

    .venv/bin/python -m pytest -v                    # fast suite (fake gateway)
    HCS_AK=... .venv/bin/python -m pytest -m cloud_contract   # real cloud

The contract suite runs each exercise against the fake and (with
credentials) the real cloud. The member bind/unbind exercise needs a
real port id on the live cloud — export `HCS_CONTRACT_PORT=<spare test
port id>` or it skips (attach appends to the port's SG list and detach
removes only ours, so a spare port keeps its other groups).

## Architecture

New to the code? `docs/architecture.md` opens with a reading order
(the eight-step click path). Summary: clean architecture rings,
AST-enforced (tests/test_architecture.py):
`model/` and `usecases/` are pure stdlib; PyYAML lives only in
`adapters/yaml_config.py`, the Huawei SDK only in
`adapters/huawei_gateway.py`; `cli/` is a thin argparse layer. The
in-memory `adapters/fake_gateway.py` implements the same five
protocols — the contract suite runs one behavioural exercise against
both the fake and (with credentials) the real gateway.
