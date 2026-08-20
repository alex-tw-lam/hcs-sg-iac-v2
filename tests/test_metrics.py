# tests/test_metrics.py
"""Complexity & maintainability gate (radon) — a HARD threshold since
the v0.6.3 refactor emptied the D/F club: every block stays at
cyclomatic rank C or better (complexity <= 20) and every file keeps
maintainability rank A. A violation means: refactor it, don't bump the
threshold."""

import pathlib

from radon.complexity import cc_rank, cc_visit
from radon.metrics import mi_rank, mi_visit

PKG = pathlib.Path(__file__).resolve().parents[1] / "hcs_sg_iac"


def test_maintainability_stays_rank_a():
    for path in PKG.rglob("*.py"):
        mi = mi_visit(path.read_text(encoding="utf-8"), multi=True)
        assert mi_rank(mi) == "A", (path, mi)


def test_no_block_above_rank_c():
    for path in PKG.rglob("*.py"):
        for block in cc_visit(path.read_text(encoding="utf-8")):
            rank = cc_rank(block.complexity)
            assert rank not in "DEF", (
                f"{path.name}:{block.name} is rank {rank} "
                f"(complexity {block.complexity}) — refactor it below 21"
            )
