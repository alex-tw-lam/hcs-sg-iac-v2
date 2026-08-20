# hcs-sg Design Spec (authoritative)

Date: 2026-08-19
Status: Draft for review
Home: new repository (`hcs-sg-iac`, proposed `~/repo/hcs-sg-iac`); sibling of
`hcs-sg-batchports-api`, which keeps its batch-port-membership API service.

## 1. Vision

A Terraform-like CLI for one narrow job: **security group definitions and their
rules** on Huawei Cloud Stack 8.5.1 VPC. The group is the primary object.
Defining a group forces the author to name an architectural unit and enumerate
its members (VM NIC IPs) first; rules are then defined **between groups**
(or to/from CIDRs). Groups are self-service named by their owners.

Workflow: `validate` (code only) → `plan` (diff code vs cloud) → `apply`
(execute). Output always shows adds, changes and deletions.

Design principles, in priority order:

1. Simple: two flat YAML sections, no state file, no variables/modules.
2. Decoupled & flat: files and fields are shallow; no concept is stated twice.
3. SOLID / clean architecture: model, use cases, infrastructure and
   presentation are separate rings; third-party libraries live behind
   interfaces in adapters only.
4. UI-ready: the data structure must map 1:1 onto web forms and CLI alike.

### Non-goals

Variables, modules, workspaces, remote state, a state file of any kind,
parallelism (rate budget beats parallelism — same stance as the sibling repo),
managing anything except security groups, their rules and their membership.
IPv6 (`ethertype: IPv6`) is future work, as are `action`/`priority` rule
fields and remote address groups.

## 2. File layout & schema

A project directory (default `.`, override with `--project DIR`):

```
my-project/
  groups/           # membership only, one file per group
    web-tier.yaml
    bastion.yaml
  rules/            # rules only, one file per group (optional per group)
    web-tier.yaml
    bastion.yaml
```

Filename stem **must** equal the group name inside (`groups/web-tier.yaml`
contains `name: web-tier`). Renames are therefore delete + create; the tool
never guesses.

### 2.1 Group file — `groups/<name>.yaml`

```yaml
name: web-tier            # ^[a-z0-9][a-z0-9-]{0,63}$ (1-64 chars); must not parse as IP/CIDR
description: "Public web tier"

members:                  # membership = the IP list, this file is the truth
  - ip: 10.0.1.10         # today: ip entries only
  # future entry types: - nic: <port-uuid>   /   - vm: <ecs-name>
```

### 2.2 Rules file — `rules/<name>.yaml`

```yaml
security_group: web-tier   # which group these rules belong to

ingress:                   # who may reach members of this group
  - source: bastion        # source: group name OR CIDR
    protocol: tcp
    ports: "22,443"
  - source: 203.0.113.0/24
    protocol: tcp
    ports: "22"

egress:                    # where members of this group may go
  - destination: app-tier  # destination: group name OR CIDR
    protocol: tcp
    ports: "8080"
  - destination: 0.0.0.0/0
    protocol: tcp
    ports: "443"
```

Field rules:

- `source` / `destination`: an existing group name, or a CIDR (`0.0.0.0/0`,
  `10.0.0.0/8`; bare IP auto-/32). Ambiguity is impossible because group names
  cannot look like IPs. Model type: `Remote = RemoteGroup(name) | RemoteCidr(cidr)`.
- `protocol`: `tcp | udp | icmp | icmpv6 | all` (`all` maps to the API's
  blank protocol). Numeric protocols (`"47"`) are future work.
- `ports`: canonical string grammar `80` / `80,443` / `8000-9000` (mixable),
  1–65535, max 20 entries (Huawei multiport console cap). YAML ints and lists
  (`ports: 8080`, `ports: [22, 443]`) are accepted and normalized to the
  string form. Omitted or empty = all ports. `icmp`/`icmpv6` rules must not
  have `ports`; `all` may not carry `ports` either (empty = all ports).
- Within one rules file, no duplicate (direction, protocol, ports, remote)
  tuples.

### 2.3 Managed vs unmanaged (safety semantics)

- No rules file for a group, or a missing `ingress:` / `egress:` section:
  **unmanaged** — the tool never touches those cloud rules. `plan` lists them
  under `NOT MANAGED` so users can see what exists but is not governed.
- `ingress: []` / `egress: []`: explicitly remove **all** rules in that
  direction on apply (typed confirmation required).
- Whole security group deletion is never implicit. `hcs-sg destroy <name>`
  is the only path, and it requires `--yes` (plus the explicit name
  confirmation).
- Membership is strict-sync: NICs attached to the group's cloud SG whose IPs
  are not in `members:` get detached on apply. The IP list is the truth.

### 2.4 Validation layers

| Layer | Checks | Needs cloud? |
|---|---|---|
| Schema | file structure, types, name charset/uniqueness, filename = name, ports grammar, protocol values, icmp-has-no-ports, duplicate rules, dangling `source`/`destination` group refs, dangling `security_group:` ref | no |
| Cloud membership | every `ip:` entry resolves to exactly one NIC (port `fixed_ips`) in the account; zero matches or multiple matches = error listing candidates | yes |
| Overlap report | the same IP in multiple groups is allowed; reported as information | yes (byproduct) |

`validate` runs layer 1 only. `plan` runs all layers before diffing.

## 3. Delta semantics (plan / apply)

No state file. Groups are matched to cloud security groups **by name**.

Diff per group:

| Code vs cloud | Action |
|---|---|
| Group in code, not in cloud | create SG, attach member NICs, create rules |
| Group in cloud, not in code | ignored (unmanaged) unless `destroy` is invoked |
| `description` differs | in-place update (`~`) |
| Member IP not attached | attach NIC (`insert-security-groups`) |
| Attached NIC whose IP not listed | detach (`remove-security-groups`) |
| Rule in code, not in cloud | create rule |
| Cloud rule not in code, direction managed | delete rule |
| Rule present both sides but any field differs | **delete + create** (cloud rules are immutable — no update API). `plan` shows the honest pair, ordered `+ rule` then `- rule`: apply creates before deleting so there is no transient coverage gap. The `~`/change count applies to SG metadata edits only |

Rule identity for matching: (direction, protocol, normalized port set,
remote). Cloud `remote_group_id` is translated to a group name when the SG is
known in the account; `remote_ip_prefix` to a CIDR. Self-referential
rules the cloud auto-adds on SG create (remote_group_id = the SG
itself) are preserved: they participate in matching (a coded
self-reference converges against them) but are never stale — not even
a managed `[]` direction strips them.

Inventory (`hcs-sg snapshot`) costs `1 + 2N` calls (SG list, then rules
+ members per SG; +1 per 100 member IPs for NIC resolution) and can be
replayed offline: `plan/apply/destroy --snapshot FILE` resolve and plan
against the file with ZERO cloud reads and no credentials (writes still
need the real cloud). Snapshots are point-in-time artifacts, never
auto-updated after writes; `drift --snapshot FILE` diffs the live cloud
against the file, keyed by cloud IDs (duplicate names safe), rc 1 on
any drift. Rate errors carry the recent-call trail so the exact call
sequence that hit a 429 is visible in the error line.
Apply is sequential, resumable and idempotent, and only ever runs under
`--yes` (without it, `apply`/`destroy` are dry runs): every cloud write goes through
the fixed-window rate limiter (same shared 90 calls / 5 min cloud quota as the
sibling service; this tool takes a configurable budget slice, default 25).
On budget exhaustion or a cloud 429 the executor WAITS for the window to
roll over (the exceptions carry `retry_at` from the limiter; the wait is
noted on stderr) and retries the same action, so a run continues across
windows instead of stopping (Ctrl+C aborts). When the gateway reports no
retry deadline, the fallback marks remaining actions `throttled` and
re-running `apply` resumes (same semantics as the sibling's
207-partial-resume design). The planning reads (resolution + snapshot)
share the same wait-and-continue; unretryable cloud failures surface as
single `error: …` lines, never tracebacks.
Every apply appends an append-only JSONL audit record (timestamp, project,
actions, cloud IDs, quota snapshot).

## 4. CLI

Binary `hcs-sg` (pyproject console script), framework: **stdlib argparse**
(four subcommands, no dependency; the presentation layer is thin and
swappable by design). Synchronous SDK client (a CLI has no concurrency need).

```
hcs-sg validate [--project DIR] [--json]
hcs-sg plan     [--project DIR] [--json]
hcs-sg apply    [--project DIR] [--json] [--yes] [--verbose] [--snapshot FILE]
hcs-sg destroy  <name> [--project DIR] [--json] [--yes] [--verbose] [--snapshot FILE]
hcs-sg snapshot [--project DIR] [--json] [--out snapshot.json]
hcs-sg drift    --snapshot FILE [--project DIR]
```

- Credentials/config from environment (`HCS_AK`, `HCS_SK`,
  `HCS_PROJECT_ID`, `HCS_ENDPOINT`, optional CA bundle), same variables as
  the sibling service.
- **Dry run is the default; `--yes` is the single write gate.** `apply`
  and `destroy` without `--yes` only show what would happen (same output
  as `plan`) and touch nothing; they end with the hint `Dry run — re-run
  with --yes to perform these changes`. With `--yes` the preview table
  prints first (dry-run form, plus the clear-all WARNING line for
  managed+empty directions) and only then the writes run — no prompts;
  `--yes` IS the consent. `plan` (and `validate`/`schema`) accept no
  `--yes`/`--execute` — parse-time rejection with guidance ("use
  `apply --yes`"), so a read-only verb cannot be flipped into a writing
  one by flag fumbling. `--verbose` streams progress to stderr (gateway
  calls with budget, plan phases, per-action results); under `--json` the
  preview and progress go to stderr so stdout
  stays pure JSON.
- Output is single-language English (machine output must not mix languages).

### 4.1 Output (table style)

```
$ hcs-sg plan

ACTION  TYPE    GROUP      DETAIL                                     CLOUD ID
+       member  web-tier   ip 10.0.1.12 (vm=web-01)                   nic=abc-123
-       member  web-tier   ip 10.0.1.10                               nic=def-456
~       group   web-tier   description: "web" -> "Public web tier"    sg=9f3e01
+       rule    app-tier   ingress tcp 8080 from group:web-tier
-       rule    app-tier   ingress tcp 8080 from cidr:0.0.0.0/0       rule=ab12cd34
+       rule    app-tier   ingress tcp 8080 from group:web-tier       rule=(new)

Plan: 2 to add, 1 to change, 2 to destroy.
Quota: 8 calls needed, 22 left in this window.

NOT MANAGED: egress rules of web-tier (3 cloud rules untouched).
NOT MANAGED: security group 'legacy-sg' (no groups/legacy-sg.yaml).
INFO: IP overlap (allowed): 10.0.1.10 in groups web-tier, monitoring.
```

Conventions: every CLOUD ID is prefixed (`nic=`, `sg=`, `rule=`); "port"
never means NIC anywhere in this tool — TCP/UDP ports are `ports`, network
interfaces are `nic`. `--json` emits the same action list as data (schema:
`{actions: [{action, type, group, detail, cloud_id}], summary, quota,
unmanaged, overlap}`).

`apply --yes` prints the same table with a `RESULT` column (`ok`,
`throttled`, `failed` + error) and a closing summary line; a dry-run
`apply` prints the plan table plus the dry-run hint.

## 5. Clean architecture

Dependency rule: imports point inward only. The inner two rings are pure
Python with zero third-party imports — enforced by an AST-based architecture
test (same spirit as the sibling repo's `tests/test_modularity.py`).

```
presentation   cli/          argparse entrypoint, table & JSON renderers
infrastructure adapters/     huawei_gateway.py (ONLY file importing the SDK),
                             yaml_config.py (ONLY file importing PyYAML),
                             fake_gateway.py (in-memory), audit.py (JSONL),
                             ratelimit.py (copied from sibling, stdlib)
use cases      usecases/     validate, resolve, plan (diff engine), apply,
                             pipeline (orchestration; loader/gateway injected),
                             destroy (in plan)
model          model/        Group, Member, Rule, Remote, ports parser,
                             CloudGateway & friends (Protocols), from_dict
                             constructors with full-error reporting
```

- **Model is the schema.** `Group.from_dict` / `Rule.from_dict` consume plain
  dicts (the canonical serialized shape), coerce types (int/list ports →
  string), and report **all** violations at once with file/key context.
  No parallel schema layer (no pydantic DTO) — one definition, no drift.
  YAML syntax errors (indentation etc.) are adapter concerns and carry YAML
  line numbers; semantic errors are model concerns.
- **Ports** (interfaces, segregated): `MembershipReader` (resolve IP → NIC,
  list attached NICs), `SgReader` (list SGs + rules), `SgWriter` (create/
  update/delete SG), `SgRuleWriter` (create/delete rule), `NicBinder`
  (attach/detach). `plan` depends only on readers; `apply` also on writers.
- **Adapters** implement the protocols: `huawei_gateway.py` wraps the sync
  VpcClient, funnels every call through the rate limiter, translates
  exceptions to the domain errors (`QuotaExhausted`, `CloudThrottled`,
  `CloudError`). `yaml_config.py` does file discovery, `yaml.safe_load`,
  and hands dicts to the model constructors.
- **Presentation** renders one action list two ways (table / JSON) from a
  single renderer module — no duplicated formatting logic.

Third-party dependencies: `PyYAML`, `huaweicloudsdkvpc` (dev: `pytest`).
No click/typer, no pydantic.

## 6. Cloud API mapping (HCS 8.5.1 VPC OpenAPI)

| Domain action | API |
|---|---|
| List SGs / rules | `GET /v1/{project}/security-groups`, `GET /v1/{project}/security-group-rules` |
| Create / update / delete SG | `POST/PUT/DELETE /v1/{project}/security-groups[/{id}]` |
| Resolve member IPs | `GET /v1/{project}/ports` (`fixed_ips[].ip_address`), paginated |
| Attach / detach NIC | `PUT /v3/{project}/ports/{id}/insert-security-groups`, `.../remove-security-groups` |
| Create / delete rule | `POST/DELETE /v1/{project}/security-group-rules[/{id}]` |

Rule fields: `direction` (`ingress`/`egress` — our terms are API-canonical),
`protocol` (blank = all; our `all` translates to blank), `port_range_min/max`
(v1 has no multiport: one code rule with `"22,443"` becomes two cloud rules —
the diff engine expands multi-entry specs into single-range sub-rules so
quota accounting counts splits and plans converge), `remote_group_id` XOR
`remote_ip_prefix` (our `Remote` maps directly; bare IP auto-/32), `ethertype`
fixed `IPv4` (future field in our schema when IPv6 lands). ICMP rules carry
type/code in the port fields on the wire — the adapter never parses them as
ports.

API-surface notes verified against huaweicloudsdkvpc 3.1.210 (v2 SDK):
security groups use the native v1 requests, but the SDK's
`CreateSecurityGroupOption` has no description field — a described create is
create + Neutron `PUT /v2.0/security-groups/{id}` update (2 limiter-choked
calls); rules ride the Neutron v2.0 endpoints
(`GET/POST/DELETE /v2.0/security-group-rules`); membership reads filter
ports by `fixed_ips=ip_address=...` (never by port id, which filters UUIDs);
attach/detach use the proven update-port pattern. A dispatch-table test
asserts every request class pairs with its SDK client method.

If the published HCS 8.5.1 surface turns out to lack any endpoint above,
the adapter isolates the workaround (e.g. port-update fallback for
attach/detach, as the sibling service already does) — inner rings unaffected.
Feasibility check against the real endpoint list is implementation step 0.

## 7. Testing strategy

- **Architecture test** (AST): every file under `model/` and `usecases/`
  imports only stdlib + intra-project inner rings; adapters import their one
  designated third-party library only; violation fails CI.
- **Model unit tests**: `from_dict` coercion & full-error reporting; ports
  grammar (ranges, mixing, 20-entry cap, icmp/all rejection); name charset;
  Remote disambiguation.
- **Use case tests (pure)**: each validation rule; diff matrix — create/
  delete group, description change, member add/remove, rule create/delete,
  changed-rule-as-delete+create pair, unmanaged directions untouched,
  `[]` destruction flagged for confirmation, rate-exhaustion
  wait-and-retry (and the no-deadline throttle fallback).
- **Adapter tests**: yaml loader (bad YAML → line numbers; dangling refs;
  filename≠name), gateway with a fake SDK client (request shaping, v1 port
  splitting, exception translation, limiter accounting).
- **Contract tests**: one suite run against both the in-memory fake gateway
  (used by all fast tests and e2e) and, when credentials exist, the real
  gateway behind a `cloud_contract` marker — same protocol, same
  expectations (LSP made executable).
- **CLI end-to-end**: argv → rendered table/JSON with a fake gateway
  injected; dry-run default (`apply`/`destroy` without `--yes` perform
  zero gateway writes, asserted via the fake's call log); confirmation
  prompts; `--json` shape stability.
- **Error paths are first-class**: quota exhaustion mid-apply, IP resolving
  to zero/multiple NICs, unknown group refs, malformed files — each has a
  named test asserting the user-facing message.

## 8. Future extensions (reserved, not built)

`nic:` / `vm:` member entry types; CIDR-valued member groups;
`remote_address_group_id` (IP address groups); `ethertype` IPv6; numeric
protocols; rule `action`/`priority`; web UI as an additional adapter over the
same model; per-project shared group registry.

## 9. Decision log

| # | Decision | Rationale |
|---|---|---|
| 1 | YAML, flat, two top-level dirs (G3+G4) | user choice; comments, git-friendly, form-friendly |
| 2 | No state file; name matching; IP list = truth | simplicity; forces architecture discipline |
| 3 | Rules live in `rules/` per group; ingress/egress sections | user choice; membership and policy decouple |
| 4 | Table output (O2) with +/~/- | user choice |
| 5 | `source:`/`destination:` (not from/to) | Huawei console-canonical terms |
| 6 | `security_group:` header (not `group:`) | avoid clash with remote-group refs |
| 7 | `members:` kept (not instances:) | our abstraction; entry discriminators carry types |
| 8 | `protocol: all` (not any) | Huawei has no `any` value; blank = all |
| 9 | NIC never called "port"; prefixes `nic=/sg=/rule=` | junior-review finding; port homonym was the top landmine |
| 10 | `destroy` is a subcommand, typed-name confirm | terraform convention; most dangerous op |
| 11 | Missing file/section = unmanaged; `[]` = remove all (confirmed) | removes the invisible-default footgun |
| 12 | Rule edits shown as honest `-`/`+` pair | cloud rules immutable; no fake `~` |
| 13 | argparse, sync SDK | thin presentation rim; stdlib-first family style |
| 14 | Model self-validating; no pydantic | single schema, zero duplication |
| 15 | CIDR allowed in source/destination from day one | public/office sources otherwise inexpressible |
| 16 | New repo `hcs-sg-iac` | user choice; sibling repo untouched |
| 17 | Dry run by default; `--yes` is the single write gate (consent after preview) | user requirement — safety must be opt-in, not opt-out |
