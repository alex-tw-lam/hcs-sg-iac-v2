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

    groups/web-tier.yaml         # name, description, members: [ip: ...]
    rules/web-tier.yaml          # security_group, ingress(source:), egress(destination:)

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

## JSON Schema

Editor/validation schemas for the config files, generated from the model
(single source of truth — patterns and enums come from the model
constants, a drift guard test pins the committed copies):

    hcs-sg schema group           # groups/<name>.yaml schema
    hcs-sg schema rules           # rules/<name>.yaml schema
    hcs-sg schema                 # both, keyed

Static copies live in `schemas/*.schema.json` (JSON Schema draft
2020-12); a drift-guard test pins them to a fresh export. Regenerate
after model changes:

    hcs-sg schema group > schemas/group-file.schema.json
    hcs-sg schema rules > schemas/rules-file.schema.json Single-file constraints only — filename==name, cross-file
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

## Tests

    .venv/bin/python -m pytest -v                    # fast suite (fake gateway)
    HCS_AK=... .venv/bin/python -m pytest -m cloud_contract   # real cloud

## Architecture

Clean architecture rings, AST-enforced (tests/test_architecture.py):
`model/` and `usecases/` are pure stdlib; PyYAML lives only in
`adapters/yaml_config.py`, the Huawei SDK only in
`adapters/huawei_gateway.py`; `cli/` is a thin argparse layer. The
in-memory `adapters/fake_gateway.py` implements the same five
protocols — the contract suite runs one behavioural exercise against
both the fake and (with credentials) the real gateway.
