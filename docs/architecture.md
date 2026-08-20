# Architecture

The architecture's one rule: **imports point inward; the inner rings never
know the outer ones exist.** A test enforces it (see below).

```
presentation   cli/          argparse entry, render (table/JSON)
                             api/ or gui/ would live HERE as siblings
infrastructure adapters/     yaml_config (PyYAML), huawei_gateway (SDK),
                             fake_gateway (in-memory), ratelimit, audit
use cases      usecases/     validate · resolve · plan (diff) · apply ·
                             pipeline (orchestration)
model          model/        entities · portset · remote · actions ·
                             cloud · gateway (five Protocols) · report · errors
```

## Rings and their one-line jobs

| Ring | Modules | Responsibility |
|---|---|---|
| model | `entities` `portset` `remote` `actions` `cloud` `gateway` `report` `errors` | The vocabulary. "The model IS the schema": from-dict constructors validate everything and report ALL violations. Pure stdlib. |
| usecases | `validate` `resolve` `plan` `apply` `pipeline` | The verbs. Pure logic over model types + Protocols; no I/O of their own. |
| adapters | `yaml_config` `huawei_gateway` `fake_gateway` `ratelimit` `audit` | The only ring that touches third-party libraries. Each adapter owns exactly one external thing. |
| cli | `main` `render` | Thin presentation: parse argv → call `pipeline` → render. |

`usecases/pipeline.py` is the orchestration seam: it sequences
load → validate → resolve → snapshot → plan (and for `--yes`:
confirm-hook → execute → audit). The CLI is one consumer; a future web API
or GUI is another — presentation layers provide their own confirmation
hooks and renderers, the pipeline is shared.

## Enforcement

`tests/test_architecture.py` AST-checks every file:

- model/ and usecases/ import stdlib + `hcs_sg_iac` only — never PyYAML,
  never the SDK
- each adapter file imports exactly its designated third-party root
  (`yaml_config`→yaml, `huawei_gateway`→huaweicloudsdkcore/vpc, others none);
  an unregistered adapter file FAILS, so additions are deliberate
- ring direction: usecases may import model only; adapters may import
  model plus same-ring adapter modules (`huawei_gateway` uses `ratelimit`)
  — never usecases or cli; model imports nothing inward of itself

## The five Protocols (the portability boundary)

`model/gateway.py` defines the cloud boundary as five small Protocols:
`SgReader` / `SgWriter` / `SgRuleWriter` / `MembershipReader` / `NicBinder`.
Everything cloud-specific — name→UUID remote resolution, ICMP type/code on
the wire, ethertype, attach mechanics, pagination, quota reporting — lives
behind them in adapters. `fake_gateway` (in-memory) and `huawei_gateway`
(SDK) implement the same five, and the contract suite
(`tests/contract/`) runs one behavioural exercise against both, so the
fake can never silently diverge from the real cloud.

## Extension guide

| To add… | Touch | Notes |
|---|---|---|
| Web API / GUI | new `api/` / `gui/` package next to `cli/`, calling `usecases/pipeline` | zero changes in model/usecases/adapters |
| Second cloud (AWS…) | new `adapters/<cloud>_gateway.py` + register it in `tests/test_architecture.py` + a contract fixture | the five Protocols are the contract; mind ICMP type/code fidelity and pagination |
| `- nic:` / `- vm:` member entries | model/entities (Member becomes a tagged union), gateway Protocols (find-by-port/vm), resolve (join key), plan | the biggest ripple today: `ip` is the join key across rings; migrate the join key to port_id when undertaking this |
| IPv6 / ethertype | model/remote (rejection sites), entities, cloud (CloudRule.ethertype), huawei translate | every rejection is centralized with one message |
| Rule description | Rule + CloudRule fields; drift shows as delete+create pair (rules are immutable) | no update port exists by design |

## Known warts (deliberate)

- `ratelimit.py` is a verbatim copy of the sibling repo's module
  (copy-purity beats a one-line header fix) — its header still says
  `app/ratelimit.py`.
- `plan.py` was born as `diff.py`; the rename happened when the file was
  otherwise touched (2026-08-20 refactor).
- `Action.detail` is display text. Behavioural decisions never parse it;
  structured facts (e.g. the clear-all set) travel as data on ActionList.
