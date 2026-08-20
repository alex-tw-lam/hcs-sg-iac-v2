# tests/test_frames_coverage.py
"""The coverage guard (docs/testing-strategy.md): the frame table in
tests/specs/frames.py is the single source of truth — DEFERRED entries
must carry a reason, ids must be unique, rows must carry their tier
routing, and the hand-written tier-4 ids must exist in the contract
suite. The every-row-interpreted check lives in tests/conftest.py as an
in-process collection hook (no subprocess, silent on subset runs)."""
import pathlib

from tests.specs.frames import DEFERRED, FRAMES, TIER4

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_CONTRACT = (_ROOT / "tests" / "contract"
             / "test_gateway_contract.py").read_text(encoding="utf-8")


def test_frame_ids_are_unique():
    ids = [f.id for f in FRAMES]
    assert len(ids) == len(set(ids)), \
        f"duplicated frame ids (suffix the literal variants): " \
        f"{sorted(i for i in ids if ids.count(i) > 1)}"


def test_no_row_is_also_deferred():
    overlap = {f.id for f in FRAMES} & set(DEFERRED)
    assert not overlap, f"ids both row and DEFERRED: {sorted(overlap)}"


def test_deferred_entries_have_reasons():
    for fid, reason in DEFERRED.items():
        assert isinstance(reason, str) and reason.strip(), fid


def test_rows_carry_their_tier_routing():
    for f in FRAMES:
        if f.tier == 1:
            assert f.model_call, f.id
        elif f.tier == 2:
            assert f.usecase, f.id
        elif f.tier == 3:
            assert f.argv or f.model_call == "load_config", f.id
        else:
            raise AssertionError(f"{f.id}: tier must be 1-3 (tier 4 is TIER4)")


def test_tier4_stays_hand_written_in_the_contract_suite():
    for fid, description in TIER4.items():
        assert fid in _CONTRACT, \
            f"{fid} ({description}) missing from {_CONTRACT}"
