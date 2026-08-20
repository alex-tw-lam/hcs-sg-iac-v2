# tests/test_metrics.py
"""Complexity & maintainability ratchet (radon): every file stays at
maintainability rank A, and the D/F complexity club may not gain new
members. The two known F hot spots (cli main(), plan()) are the pending
split-main refactor — the ratchet guarantees they cannot quietly grow
a crowd while nobody watches."""

import pathlib

from radon.complexity import cc_rank, cc_visit
from radon.metrics import mi_rank, mi_visit

PKG = pathlib.Path(__file__).resolve().parents[1] / "hcs_sg_iac"

# blocks at radon rank D/F today, keyed by file name (the ratchet floor:
# these may improve/disappear, nothing else may join)
DF_CLUB = {
    "main.py": {"main"},
    "plan.py": {"plan"},
    "portset.py": {"parse_ports"},
    "apply.py": {"execute"},
    "importer.py": {"import_snapshot"},
    "render.py": {"render_plan"},
}


def test_maintainability_stays_rank_a():
    for path in PKG.rglob("*.py"):
        mi = mi_visit(path.read_text(encoding="utf-8"), multi=True)
        assert mi_rank(mi) == "A", (path, mi)


def test_no_new_def_ranked_blocks():
    for path in PKG.rglob("*.py"):
        allowed = DF_CLUB.get(path.name, set())
        for block in cc_visit(path.read_text(encoding="utf-8")):
            rank = cc_rank(block.complexity)
            if rank in "DEF":
                assert block.name in allowed, (
                    f"{path.name}:{block.name} joined the D/F complexity "
                    f"club (rank {rank}, {block.complexity}) — refactor it "
                    f"or deliberately add it to the ratchet"
                )
