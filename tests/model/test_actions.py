# tests/model/test_actions.py
"""Row coverage: ACT-01/ACT-02 (ActionList.summary) live in
tests/specs/frames.py. These payload pins are not expressible as rows:
constructor positional/keyword equality and the ActionResult default."""

from hcs_sg_iac.model.actions import Action, ActionResult, UpdateSg


def test_action_result_defaults():
    ar = ActionResult(
        action=Action("+", "rule", "g", "d", None, None), status="ok"
    )
    assert ar.error is None


def test_update_sg_carries_sg_id():
    assert UpdateSg(sg_id="sg-1", description="d") == UpdateSg("sg-1", "d")
