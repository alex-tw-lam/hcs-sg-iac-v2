"""hcs-sg: security-group-as-code for Huawei Cloud Stack.

Three vocabulary leaves, three rings; imports point inward (tach.toml
enforces it; the per-file third-party designation lives in
tests/test_architecture.py).

    entities.py     the DESIRED state — YAML entities + the ports
                    grammar + the collect-all Report
    snapshot.py     the OBSERVED state — CloudSg/CloudRule/CloudNic +
                    the snapshot.json codec
    contracts.py    the cloud boundary — CloudReader/CloudWriter
                    Protocols + CloudError

    usecases/       the verbs — plan · apply · pipeline · resolve ·
                    drift · importer (+ actions, the plan vocabulary)
    adapters/       the ONLY third-party ring — SDK, PyYAML, fakes,
                    snapshots
    cli/            thin presentation — argv in, tables/JSON out

Naming that pays off once seen: Group/Rule (entities) are the DESIRED
state from YAML; CloudSg/CloudRule/CloudNic (snapshot) are the OBSERVED
state a gateway returned; usecases.plan diffs the two by identity
tuples and emits one ActionList carrying both the display rows and the
executable payloads. The full story: README §Architecture.
"""
