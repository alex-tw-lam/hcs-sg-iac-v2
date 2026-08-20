# hcs-sg — security-group-as-code for Huawei Cloud Stack 8.5.1

One rule: **dry run is the default; `--yes` is the only path to real
writes, and the preview always prints before them.**

## Install & configure

    uv tool install .            # or: pipx install .
    export HCS_AK=... HCS_SK=... HCS_PROJECT_ID=... HCS_ENDPOINT=...
    # optional: CA_BUNDLE=/path/ca.pem   SSL_VERIFY=false   SERVICE_CALL_BUDGET=25

Credentials come from the environment only — never from files or flags.

## Usage

    hcs-sg validate [--project DIR]     # files only, zero cloud calls
    hcs-sg plan                         # diff code vs cloud (read-only)
    hcs-sg apply [--yes]                # dry run unless --yes
    hcs-sg destroy NAME [--yes]         # detach members, delete the SG
    hcs-sg snapshot [--out FILE]        # whole cloud -> snapshot.json
    hcs-sg drift [--snapshot FILE]      # live cloud vs the file (rc 1 on drift)
    hcs-sg import [--force]             # snapshot -> security-groups/ YAML

Shared flags sit after the verb: `--project DIR --json --verbose
--snapshot FILE` (+ `--yes` on apply/destroy).

## Project files

Per-SG directory layout — the directory name IS the group name:

    security-groups/web/
    ├── group.yaml          # name, description, members: [{ip: ...}]
    ├── ingress.yaml        # list of {source, protocol, ports}
    └── egress.yaml         # list of {destination, protocol, ports}

`source`/`destination` = group name or IPv4 CIDR (bare IP auto-/32).
Protocol: tcp|udp|icmp|icmpv6|all. Ports: `"80"`, `"22,443"`,
`"8000-9000"` (merged, max 20 entries). An absent direction file =
UNMANAGED (the tool never touches those cloud rules; `plan` lists them
under NOT MANAGED); `[]` = managed remove-all (flagged with a WARNING
line). The self-referential rules HCS adds on SG create are preserved —
never converged away, not even by `[]`; a coded self-reference matches
them instead of duplicating. Multi-environment repos conventionally use
`projects/<env>/` siblings (`--project projects/dev`).

## Snapshot, drift, import

`snapshot` takes the WHOLE estate in 2 paged calls (SGs with embedded
rules + one unfiltered port list). With `snapshot.json` present,
plan/apply/destroy run their pre-work fully OFFLINE — zero reads, no
credentials — and `apply --yes` still writes live. After a write run
the snapshot is deliberately NOT auto-updated: the CLI notes staleness;
refresh with `snapshot` or verify with `drift` (keyed by cloud IDs, so
duplicate names never confuse it; `drift --json` is Liquibase-diff
shaped). `import` adopts the estate from a snapshot (offline): every
unrepresentable thing is skipped WITH a note (bad names, duplicate
cloud names, IPv6 remotes); a skipped rule becomes an honest stale
delete on the next plan — the note says so. Import refuses to
overwrite existing files without `--force`; delete a file to unmanage.

## Safety

- Every write path goes through the preview table first; `--yes` is
  the consent, there are no prompts.
- Rate limits: a fixed-window limiter guards every call; exhaustion
  and cloud 429s WAIT out the window and continue (bounded retries) —
  an unattended run finishes instead of stopping. Raise
  SERVICE_CALL_BUDGET toward the cloud cap (~90/5min) for big estates.
- Member identity is the IP list; resolution fails clean on zero or
  multi-match before any write.
- Whole-group deletion only via explicit `destroy NAME --yes`.

## Checks & tests

    .venv/bin/python -m black .                  # format (79 cols)
    .venv/bin/python -m ruff check .             # lint
    .venv/bin/python -m mypy                     # types (prod ring)
    .venv/bin/tach check                         # ring direction (tach.toml)
    .venv/bin/python -m pytest -q                # behaviour
    .venv/bin/radon cc hcs_sg_iac -n C -s        # complexity report (no block above rank C)
    .venv/bin/radon mi hcs_sg_iac -s             # maintainability (all rank A)
    trivy fs --scanners vuln,secret --skip-dirs .venv .   # CVEs + secrets

Trivy reads uv.lock when present; `.trivyignore` records the one
vendor-blocked acceptance (the SDK caps pyasn1 at 0.6.3 — see the file
for the reason and re-review trigger). First trivy run downloads the
vulnerability DB; the air-gapped RHEL box needs the offline DB (trivy
docs: "Air-Gapped Environment") or simply runs the scan elsewhere.

Real-cloud contract tests (fake always, real gated on credentials):

    HCS_AK=... .venv/bin/python -m pytest tests/test_gateway_contract.py
    # member bind/unbind on the real cloud additionally needs
    # HCS_CONTRACT_PORT=<id of a spare test port>

## Architecture

Clean rings, one rule: imports point inward; inner rings never know
outer ones exist.

    cli/        thin presentation — argv in, tables/JSON out
    usecases/   the verbs — plan · apply · pipeline · resolve · drift ·
                importer
    adapters/   the ONLY third-party ring — SDK, PyYAML, fakes, snapshots
    model/      the vocabulary — entities · actions · cloud · common

Two seams, enforced two ways: **ring direction** by `tach check`
(tach.toml, four ring-level modules — sibling imports inside a ring
are internal by construction); **per-file third-party designation**
by tests/test_architecture.py (yaml_config→yaml, huawei_gateway→SDK;
an unregistered adapter file FAILS). The cloud boundary is TWO
Protocols (model/gateway.py): CloudReader (inventory() is the single
read seam + find_nics_by_ip) and CloudWriter. Three interchangeable
gateways implement them — huawei (SDK), fake (in-memory, powers every
test), snapshot replay (offline planning) — and the contract suite
runs the same exercise against fake and real so the fake cannot drift
from reality unnoticed. Desired state (`Group`/`Rule`) vs observed
(`CloudSg`/`CloudRule`) join on identity tuples
`(direction, protocol, ports, remote)`; plan output is ONE ActionList
carrying both display rows and executable payloads.
