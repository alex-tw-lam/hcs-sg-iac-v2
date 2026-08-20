# hcs-sg-iac

Security-group-as-code for Huawei Cloud Stack 8.5.1. Groups first
(members = VM NIC IPs), then rules between groups (or CIDRs).
Dry run by default — `--execute` is the only path to real writes.

## Install

    python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

## Configure

    set -a; source .env; set +a      # see .env.example

## Usage

    hcs-sg validate                  # files only, no credentials
    hcs-sg plan                      # diff code vs cloud (read-only)
    hcs-sg apply                     # dry run; add --execute to write
    hcs-sg apply --execute           # prompts typed 'yes' unless --yes
    hcs-sg destroy web-tier --execute   # prompts the group name

## Project files

    groups/web-tier.yaml         # name, description, members: [ip: ...]
    rules/web-tier.yaml          # security_group, ingress(source:), egress(destination:)

`source`/`destination` = group name or CIDR (`0.0.0.0/0`, bare IPs
auto-/32). Protocol: tcp|udp|icmp|icmpv6|all. Ports: "80", "22,443",
"8000-9000" (max 20 entries after merging; unquoted ints and YAML lists
accepted). A missing `ingress:`/`egress:` section (or no rules file at
all) = unmanaged — the tool never touches those cloud rules and `plan`
lists them under NOT MANAGED; `[]` = remove all rules in that direction
(extra confirmation). File names must equal the group name.

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
  slice defaults to 25 per window (SERVICE_CALL_BUDGET). Exhausted or
  cloud-throttled (429): the run waits out the window (notice on stderr)
  and retries — it continues across windows instead of stopping; Ctrl+C
  aborts. If the gateway can't report a retry deadline, remaining
  actions are marked throttled and re-running `apply` resumes
  (idempotent).
- `SSL_VERIFY=false` also mutes the noisy Unverified-HTTPS warnings
  (you already opted out; the tool won't nag about it on every call).
- Every `--execute` run appends a record to `audit.jsonl` in the
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
