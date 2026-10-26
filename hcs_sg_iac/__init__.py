"""hcs-sg: security-group-as-code for Huawei Cloud Stack.

    entities.py   what the YAML WANTS — groups, rules, ports grammar
    snapshot.py   what the cloud HAS — one observation + the file
    contracts.py  the cloud boundary — read/write method sets
    engine.py     the diff brain — resolve · plan · execute · drift
    adapters/     the only files touching third-party libraries
    cli/          argv in, tables and JSON out

The one idea: every rule carries an identity tuple (direction,
protocol, ports, remote) — the YAML's rules and the cloud's rules are
matched by it, and engine.plan emits one ActionList that serves both
the preview and the executor. Imports point inward; tach.toml and
tests/test_architecture.py enforce it. The full story:
README §Architecture.
"""
