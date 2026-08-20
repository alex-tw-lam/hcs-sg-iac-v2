# tests/conftest.py
"""Shared pytest hooks.

Frame-coverage guard, in-process: when the three frame consumers are all
being collected, every frame row must be interpreted by at least one
collected case (docs/testing-strategy.md). Runs at ~0ms on full runs and
stays silent on subset runs (single-file debugging must not trip it).
"""

import pytest

_CONSUMERS = {
    "tests/test_frames_model.py",
    "tests/test_frames_usecase.py",
    "tests/test_frames_cli.py",
}


def pytest_collection_modifyitems(session, config, items):
    collected_files = {item.nodeid.split("::")[0] for item in items}
    if not collected_files >= _CONSUMERS:
        return  # subset run — guard stays silent
    from tests.specs.frames import FRAMES

    interpreted = {
        item.nodeid.rsplit("[", 1)[-1].rstrip("]")
        for item in items
        if item.nodeid.split("::")[0] in _CONSUMERS
    }
    missing = [f.id for f in FRAMES if f.id not in interpreted]
    if missing:
        raise pytest.UsageError(
            f"frame rows no consumer interprets: {missing} — every "
            f"tests/specs/frames.py row needs a tier-routed consumer case"
        )
