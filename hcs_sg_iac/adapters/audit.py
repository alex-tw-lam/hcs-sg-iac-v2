# hcs_sg_iac/adapters/audit.py
"""Append-only JSONL audit sink. The CLI wraps execute()'s audit callback
with project/quota context before the record hits disk
(docs/design-spec.md §3); the quota context is captured pre-execute —
what this run began with."""
import json


def jsonl_sink(path):
    def sink(record: dict) -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    return sink


def enrich(base_sink, **context):
    """Wrap a sink, adding static context (project, quota snapshot) to
    every record before writing."""
    def sink(record: dict) -> None:
        base_sink({**context, **record})
    return sink
