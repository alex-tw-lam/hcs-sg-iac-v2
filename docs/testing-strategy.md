# Testing Strategy

## Goals

1. The whole suite runs **without any Huawei Cloud access** — every day,
   in CI, offline.
2. Integration against the real cloud is **on demand** behind one pytest
   marker, safe to run (creates and cleans up its own resources).
3. Test design is systematic, not ad-hoc: the **Category Partitioning
   Method (CPM)** produces an abstract specification; concrete tests are
   interpretations of it. The abstract layer is the maintainable one.

## The four tiers

| Tier | What | Runs | Where |
|---|---|---|---|
| T1 model-unit | pure constructors/parsers (`parse_group`, `parse_ports`, `parse_remote`, actions, report) | always | `tests/model/` |
| T2 loader/usecase/adapter | `yaml_config`, `validate`, `resolve`, `plan`, `apply`, `render`, `ratelimit`, `fake_gateway`, `huawei_gateway` translation with a stub SDK | always | `tests/adapters/`, `tests/usecases/`, `tests/cli/test_render.py`-style |
| T3 cli-e2e | argv → exit code/stdout/stderr with `FakeGateway` injected via `main(argv, gateway=…)` | always | `tests/cli/` |
| T4 cloud-contract | the real `HuaweiGateway` against the real cloud | **only** with credentials: `HCS_AK=… .venv/bin/python -m pytest -m cloud_contract` | `tests/contract/` |

Why this works without the cloud: the five Protocols in
`model/gateway.py` are the seam. T1–T3 run entirely against
`adapters/fake_gateway.py`; the contract suite runs the SAME behavioural
exercise against fake (always) and real (T4), so the fake cannot drift
from reality unnoticed. The SDK import is deferred inside the CLI, so
even `import` of the tool never needs the SDK.

## Category Partitioning, applied

Full method and frame catalogue: `docs/cpm-test-spec.md` (the abstract
test specification). Summary of the process used:

1. **Atomic units** — every field of the data files
   (`groups/*.yaml`, `rules/*.yaml`) and environment (CLI flags, env,
   cloud state) is enumerated with its possible values.
2. **Aspects** — fields group into higher-level dimensions
   (e.g. *group-name validity*, *direction governance*, *rule identity*,
   *member resolution*, *execution budget*). Each aspect is partitioned
   into mutually exclusive categories with exact literals.
3. **Constraints** — documented impossibilities (e.g. "icmp implies no
   ports", "multi-match resolution excludes overlap reporting") prune
   combinations.
4. **Frames** — valid combinations of choices, each with an expected
   OBSERVABLE behaviour and a tier. The executable catalogue is
   `tests/specs/frames.py`; live counts and coverage state come from the
   guard (`pytest tests/test_frames_coverage.py` plus the in-process
   hook in `tests/conftest.py`), not from this document.

## Abstract vs concrete

- **Abstract**: `docs/cpm-test-spec.md` (human review) and
  `tests/specs/frames.py` (machine-readable: declarative `Frame` rows —
  project files, cloud seed, argv/stdin/env, expectations).
- **Concrete**: three tier-routed parametrized consumers
  (`tests/test_frames_model.py`, `test_frames_usecase.py`,
  `test_frames_cli.py`) interpret the rows via shared builders
  (`make_project`, `seed_gateway`, `run_cli`). Tier 4 stays hand-written
  under the `cloud_contract` marker.
- **Coverage guard**: a meta-test asserts every frame id has at least one
  passing case and reports the uncovered backlog — the frame table is the
  single source of truth.

Adding a behaviour starts with a frame (or a new category), then a row,
then (usually zero) new builder code — not a hand-written test function.

## Running

```bash
.venv/bin/python -m pytest -q                 # T1–T3, no cloud, ~seconds
.venv/bin/python -m pytest -m cloud_contract  # T4, needs HCS_* env
```
