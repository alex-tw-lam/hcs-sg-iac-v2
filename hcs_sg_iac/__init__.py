"""hcs-sg: security-group-as-code for Huawei Cloud Stack.

Four rings, one rule: imports point inward; the inner rings never know
the outer ones exist (tach.toml enforces it; the per-file third-party
designation lives in tests/test_architecture.py).

    cli/        thin presentation — argv in, tables/JSON out
    usecases/   the verbs — plan · apply · pipeline · resolve · drift ·
                importer
    adapters/   the ONLY third-party ring — SDK, PyYAML, fakes, snapshots
    model/      the vocabulary — entities · cloud · actions · common ·
                portset · quota · gateway (CloudReader/CloudWriter)

Naming that pays off once seen: Group/Rule (entities) are the DESIRED
state from YAML; CloudSg/CloudRule/CloudNic (cloud) are the OBSERVED
state a gateway returned; usecases.plan diffs the two by identity
tuples and emits one ActionList carrying both the display rows and the
executable payloads. The full story: README §Architecture.
"""
