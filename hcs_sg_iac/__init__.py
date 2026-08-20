"""hcs-sg: security-group-as-code for Huawei Cloud Stack.

Four rings, one rule: imports point inward; the inner rings never know
the outer ones exist (tests/test_architecture.py enforces it).

    cli/        thin presentation — argv in, tables/JSON out
    usecases/   the verbs — validate · resolve · plan · apply · pipeline
    adapters/   the ONLY third-party ring — SDK, PyYAML, fakes, snapshots
    model/      the vocabulary — entities · actions · cloud · gateway

Naming that pays off once seen: Group/Rule (entities) are the DESIRED
state parsed from YAML; CloudSg/CloudRule/CloudNic (cloud) are the
OBSERVED state a gateway returned; usecases.plan diffs the two by
identity tuples and emits one ActionList that carries both the display
rows and the executable payloads.

New here? Reading order: docs/architecture.md §"Reading order", then
cli/main.py:main() top-to-bottom, then model/gateway.py (five Protocols
— the whole cloud boundary), then usecases/plan.py.
"""
