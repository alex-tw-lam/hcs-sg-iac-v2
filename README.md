# hcs-sg — security-group-as-code for Huawei Cloud Stack 8.5.1

One rule: **dry run is the default; `--yes` is the only path to real
writes, and the preview always prints before them.**

## Install & configure

    uv tool install .            # or: pipx install .
    export HCS_AK=... HCS_SK=... HCS_PROJECT_ID=... HCS_ENDPOINT=...
    # optional: CA_BUNDLE=/path/ca.pem   SSL_VERIFY=false

Credentials come from the environment only — never from files or flags.

## Usage

    hcs-sg plan                         # diff code vs cloud (read-only)
    hcs-sg apply [--yes]                # dry run unless --yes
    hcs-sg snapshot                     # whole cloud -> snapshot.json
    hcs-sg drift [--snapshot FILE]      # live cloud vs the file (rc 1 on drift)
    hcs-sg import [--force]             # snapshot -> security-groups/ YAML

Shared flags sit after the verb: `--project DIR --json --verbose
--snapshot FILE` (+ `--yes` on apply).

## Project files

Per-SG directory layout — the directory name IS the group name:

    security-groups/web/
    ├── group.yaml          # name, description, members: [{ip: ...}]
    ├── ingress.yaml        # list of {source, protocol, ports}
    └── egress.yaml         # list of {destination, protocol, ports}

`source`/`destination` = group name or IPv4 CIDR (bare IP auto-/32).
Protocol: tcp|udp|icmp|all. Ports: `"80"`, `"22,443"`,
`"8000-9000"` (merged, max 20 entries). An absent direction file =
UNMANAGED (the tool never touches those cloud rules; `plan` lists them
under NOT MANAGED); `[]` = managed remove-all (flagged with a WARNING
line). **Deleting a group = removing its directory** — the plan
detaches its members and deletes the SG, `apply --yes` executes it;
an EMPTY `security-groups/` against a non-empty cloud refuses to plan
(the whole-estate guard). The self-referential rules HCS adds on SG create are preserved —
never converged away, not even by `[]`; a coded self-reference matches
them instead of duplicating. Multi-environment repos conventionally use
`projects/<env>/` siblings (`--project projects/dev`).

## Snapshot, drift, import

`snapshot` takes the WHOLE estate in 2 paged calls (SGs with embedded
rules + one unfiltered port list). With `snapshot.json` present,
plan/apply run their pre-work fully OFFLINE — zero reads, no
credentials — and `apply --yes` still writes live. After a write run
the snapshot is deliberately NOT auto-updated: the CLI notes staleness;
refresh with `snapshot` or verify with `drift` (keyed by cloud IDs, so
duplicate names never confuse it; `drift --json` prints the plain
missing/unexpected/changed diff). `import` adopts the estate from a snapshot (offline): every
unrepresentable thing is skipped WITH a note (bad names, duplicate
cloud names, IPv6 remotes); a skipped rule becomes an honest stale
delete on the next plan — the note says so. Import refuses to
overwrite existing files without `--force`; delete a file to unmanage.

## Safety

- Every write path goes through the preview table first; `--yes` is
  the consent, there are no prompts.
- Rate limits: the cloud throttling us (429 / APIGW) is waited out and
  retried in place with a bounded number of attempts — an unattended
  run finishes instead of stopping.
- Member identity is the IP list; resolution fails clean on zero or
  multi-match before any write.
- Whole-group deletion = removing the group's directory; members
  detach first (the API refuses an SG with ports), then the SG goes —
  previewed like every write, gated by `--yes`.

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

## Architecture

Four small core modules, two thin rings around them; imports only
point inward — `tach check` and tests/test_architecture.py enforce it.

    entities.py   what your YAML WANTS — groups, rules, the ports
                  grammar ("80", "22,443", "8000-9000")
    snapshot.py   what the cloud HAS — one observation, plus the
                  snapshot.json read/write
    contracts.py  the cloud boundary — the read/write method sets any
                  gateway must offer, and CloudError
    engine.py     the diff brain — resolve member IPs, plan, execute,
                  drift; no I/O of its own
    adapters/     the third-party ring — PyYAML here, the Huawei
                  SDK + tenacity there (the entities/snapshot leaves
                  carry pydantic)
    cli/          argv in, tables and JSON out

The one idea that explains the core: every rule carries an identity
tuple `(direction, protocol, ports, remote)`. Your YAML's rules and
the cloud's rules are matched by that tuple — plan output is ONE
ActionList that serves both the on-screen preview and the executor.
