# CPM Test Specification — hcs-sg-iac

Abstract test specification produced by the Category Partitioning Method.
The executable form of the frames lives in `tests/specs/frames.py`; the
concrete interpreters in `tests/test_frames_*.py` (see
`docs/testing-strategy.md`). Tiers: **T1** model-unit · **T2**
loader/usecase/adapter · **T3** cli-e2e · **T4** cloud-contract
(credentials-gated).

## 1. Field inventory (atomic units)

### 1.1 `groups/<name>.yaml`

| Field | Atomic choices |
|---|---|
| `name` | `web-tier` (valid) · `a` (single char) · `1web` (digit-leading, valid) · `"a"×64` (boundary valid) · `"a"×65` (too long) · `Web` (uppercase) · `web_tier` (underscore) · `-web` (leading hyphen) · `web-` (trailing hyphen, valid) · `10.0.1.10` (IP-lookalike) · `10.0.0.0/8` (CIDR-lookalike) · `""` · absent · `123` (non-string) |
| `description` | absent (→ `""`) · `""` · `"web"` · `5` (non-string) |
| `members` | absent (→ `[]`) · `[]` · valid list · `"10.0.1.10"` (non-list) |
| `members[i]` | `{"ip": "10.0.1.10"}` · with extra keys (tolerated) · `"10.0.1.10"` (bare string) · `{}` (no ip key) · `{"ip": 10}` · `{"ip": "999.0.0.1"}` · `{"ip": "010.0.1.10"}` · `{"ip": "::1"}` · duplicate entry |
| document | mapping · empty file · `null` · scalar · list · YAML syntax error · binary bytes |

### 1.2 `rules/<name>.yaml`

| Field | Atomic choices |
|---|---|
| `security_group` | `app-tier` (valid) · `Web` / `web_x` · absent · `""` · `42` |
| `ingress`/`egress` section | present list · `[]` (managed remove-all) · absent (unmanaged) · `null` (error) · `"80"` (non-list) · entry non-mapping (`- 80`) |
| `source`/`destination` | group name · `0.0.0.0/0` · `10.0.0.0/8` · `203.0.113.7` (→/32) · `10.0.0.1/8` (→`10.0.0.0/8`) · `10.0.0.0/99` · `tcp/80` · `2001:db8::/32` · `::1` · `""` · `" "` · absent · non-string |
| `protocol` | `tcp` · `udp` · `icmp` · `icmpv6` · `all` · absent · `sctp` |
| `ports` | absent · `None` · `""` · `[]` · `"80"` · `8080` (int) · `[22,443]` · mixed list · `"22,443"` · `"8000-9000"` · `"443,80"` (unsorted) · `"80, 443"` (spaces) · `"80,81,82"` (adjacent) · `"80,82"` (gap) · `"80,80"` (dup) · `"1-100,50-60"` (containment) · `"80-81,82-83"` · `"1-65535"` / `"1-100,101-65535"` (full range→None) · `"0"` · `"65536"` · `"70000"` · `"9000-8000"` (reversed) · `"-1"` · `"80,,443"` · `"http"` · `True` · `80.5` · `"⁸⁰"` (unicode digits) · 21 non-adjacent ports (cap error) · 20 adjacent (→`1-20`) |
| rule identity | unique · exact duplicate · canonical-equivalent duplicate (`"443,80"` vs `"80,443"`) |

### 1.3 File store

| Field | Atomic choices |
|---|---|
| `groups/` dir | missing · empty · files |
| `rules/` dir | missing · empty · files |
| extension | `.yaml` only · `.yml` sibling (warning) |
| stem vs declared name | equal · group mismatch · rules mismatch |
| duplicates | none · two group files same name · two rules files same `security_group` |
| dangling | rules file without its group file |
| encoding | UTF-8 · binary |
| accumulation | one bad file · several bad files in one load |

### 1.4 Environment / CLI

| Field | Atomic choices |
|---|---|
| `SERVICE_CALL_BUDGET` | unset (25) · `"25"` · `"40"` · `"not-a-number"` (→25) · `"0"` |
| `SSL_VERIFY` | `"true"` · `"false"` |
| credentials | all set · ≥1 missing (of AK/SK/PROJECT_ID/ENDPOINT) |
| subcommand | validate · plan · apply · destroy · none (usage) |
| `--project` | explicit · default `"."` · nonexistent |
| `--json` / `--yes` / `--verbose` | absent/present |
| stdin (apply) | `yes` · `no` · `YES` · EOF · KeyboardInterrupt |
| stdin (destroy) | exact name · wrong name · EOF |
| destroy target | cloud SG exists · unknown |

### 1.5 Cloud state (seeded)

| Field | Atomic choices |
|---|---|
| SG per code group | new · exists desc-equal · exists desc-differs |
| extra cloud SGs | none · unmanaged · two sharing one name |
| rule identity vs code | exact · remote changed · ports changed · protocol changed · direction changed · extra cloud rule · multiport split (converge/partial) · non-canonical cloud CIDR · protocol `None`↔`all` · remote fields unset↔`0.0.0.0/0` · IPv6 remote · remote_group_id known/unknown · ICMP type/code in min/max |
| direction governance | managed-rules · managed-`[]` · unmanaged-section · no-rules-file × cloud N>0 / N=0 |
| NIC per member IP | exactly 1 · 0 · ≥2 (vm_name known/unknown) |
| attachment | attached+desired · attached+undesired · desired+unattached · attached with empty ip |
| budget | `None` · `0` · `1` · sufficient N |

## 2. Aspect catalogue

A1 group-name validity · A2 description · A3 members container · A4 member
entry · A5 security_group field · A6 direction section · A7 remote · A8
protocol · A9 ports · A10 protocol–ports consistency · A11 rule-identity
uniqueness · A12 file-store integrity · A13 cross-file validation · A14
member resolution · A15 cloud group state · A16 rule identity (plan) · A17
direction governance · A18 membership drift · A19 execution · A20 CLI
interaction · A21 rendering · A22 rate limiter · A23 Huawei translation ·
A24 FakeGateway fidelity · A25 gateway contract.

(Exact category values per aspect are the unions of the field-choice rows
above; the executable truth is `tests/specs/frames.py`.)

## 3. Constraints

1. `protocol ∈ {icmp, icmpv6, all}` ⇒ ports must be absent/empty.
2. Multi-match resolution removes the IP from `nics` ⇒ excluded from
   overlap reporting.
3. New-SG excludes description-update (CreateSg carries the description).
4. `plan()` asserts resolution ok (CLI enforces rc 1 before planning).
5. Duplicate declared name is checked before filename-stem equality.
6. Any loader error ⇒ `(None, report)`; no partial DesiredState escapes.
7. Stem equality is only checked for successfully parsed documents.
8. A rules file requires its group file (dangling ⇒ error).
9. Budget exhaustion throttles all subsequent actions (rank order).
10. `--yes` rc 0 iff all results ok (throttled ⇒ rc 1).
11. destroy confirms by typed group NAME; apply confirms exact `yes`
    (case-sensitive).
12. preview table prints before any write under `--yes`.
13. Multi-entry code rules expand to single-range cloud identities.
14. `1-65535` → None (all ports); `all` ↔ cloud protocol None; unset
    remote ↔ `0.0.0.0/0`.
15. Unrepresentable cloud remote ⇒ never-matching identity ⇒ honest delete.
16. Duplicate cloud SG names abort planning (rc 1).
17. Cloud SG without code is never deleted by plan/apply (destroy only).
18. `.yml` files never parsed (warning only, both dirs).
19. >20 merged port entries ⇒ error; 20 adjacent ⇒ `"1-20"`.
20. `audit.jsonl` only on `--yes`; quota context is pre-execute.
21. Clear-all WARNING only for managed-empty directions with actual
    `-` rule rows in the plan.
22. FakeGateway budget is its own attribute (substitute for env budget).

## 4. Frame specifications

The authoritative, executable enumeration is `tests/specs/frames.py` —
one row (or a family of literal rows, suffixed `.a`/`.b`/…) per frame,
each with tier, choices and expected observable behaviour, every
expectation verified by running it. The tier-routed consumers
(`tests/test_frames_{model,usecase,cli}.py`) interpret the rows; frames
that the declarative format cannot carry are `DEFERRED` there with a
reason (tier-4 lives hand-written in `tests/contract/`). Row counts and
coverage state are deliberately NOT mirrored in this document — run
`.venv/bin/python -m pytest tests/test_frames_coverage.py` (plus the
in-process hook in `tests/conftest.py`) for the live truth.

### T1 model-unit (frames NAME-01…04, DESC-01…02, MEMB-01…02, MIP-01…06, SGF-01…02, SECT-01…06, REMOTE-01…07, PROTO-01…02, PORTS-01…08, PP-01…03, DUPRULE-01, ACT-01…02, MODEL-01)

Highlights: valid names include `a`, `1web`, 64-char, `web-`; invalid
charset/length family error with the regex; IP/CIDR-lookalike names error
with the IP/CIDR message (checked before charset); absent/non-string name
errors; sections: present/[]/absent/null(→error with remove-all
guidance)/non-list/non-mapping-entry; remotes: group, CIDR, normalising
(/32, host-bit masking), invalid, IPv6, empty, missing; ports: the full
grammar table incl. full-range→None, sort/merge family, bounds, cap,
junk; protocol–ports consistency; duplicate rule identity incl.
canonical-equivalent.

### T2 loader/usecase/adapter

Highlights (families and literals per `tests/specs/frames.py`, the
authoritative enumeration): store integrity family (missing dir, empty project ok,
degenerate docs, syntax errors with line numbers, binary, .yml warnings,
stem mismatches, duplicates, dangling, multi-error accumulation);
resolution exact/zero/multi/overlap/mixed; rate limiter
budget/rollover/external-throttle/snapshot; Huawei translation (dispatch
existence AND pairing, rule translation incl. icmp type/code, chokepoint,
remote-id cache, fixed_ips filter, chunking); plan engine (new group
ordering with sg_id="" payloads, description update, unmanaged inventory
incl. no-rules-file, managed-[] delete-all, identity equivalence family,
changed rule = honest +/- pair, multiport converge/partial, overlap dedupe,
unrepresentable remote, remote_group_id known/unknown, membership
add/remove/vm-detail, destroy ordering); execution (rank order,
id-substitution, budget 0/1/N, failure isolation + dependent skip,
throttle-resume convergence, audit record shape, op-None skip); rendering
(prefixes, pairing, footers, json shape).

### T3 cli-e2e

Highlights (families and literals per `tests/specs/frames.py`): validate ok/invalid + no gateway touched; no-write modes
(plan, default apply) with zero call_log;
execute confirmations (yes/no/YES/EOF/KeyboardInterrupt/--yes-skip);
clear-all warning precision; credentials gate (names all four vars);
--json modes; destroy confirmations and unknown name; throttled ⇒ rc 1;
env config family; audit.jsonl; default/nonexistent project; duplicate
cloud names clean error; post-execute quota freshness.

### T4 cloud-contract (CTRCT-01…02)

CTRCT-01 full protocol exercise (fake always, real gated, cleanup-safe).
CTRCT-02 extended protocol round-trip (udp, icmp type/code on the wire,
all) — real cloud only meaningful additions.

## 5. Coverage

The initial 2026-08-20 design pass catalogued the backlog (18
fully-uncovered frames plus partial literals); it is now closed — every
catalogued frame is either a row in `tests/specs/frames.py`, a `DEFERRED`
entry there with a reason (the five XLATE frames whose stub-SDK
harnesses the declarative format cannot carry — their depth home is
`tests/adapters/test_huawei_translate.py`), or hand-written tier 4 in
`tests/contract/`. Live counts and coverage state come from the guard
(`pytest tests/test_frames_coverage.py` plus the in-process hook in
`tests/conftest.py`), not from this document.
