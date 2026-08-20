# tests/test_frames_cli.py
"""Tier-3 consumer: interprets tier-3 Frame rows (tests/specs/frames.py)
as argv -> rc/stdout/stderr against main() with a seeded FakeGateway
(the env-config family exercises load_config directly)."""
import json

import pytest

from hcs_sg_iac.cli.main import load_config, main
from tests.specs.builders import check_cloud, make_project, seed_gateway
from tests.specs.frames import RAISE_EOF, RAISE_KI, TIER3


@pytest.mark.parametrize("frame", TIER3, ids=lambda f: f.id)
def test_frame(frame, tmp_path, capsys, monkeypatch):
    if frame.model_call == "load_config":     # env-config family
        for key, value in (frame.env or {}).items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        config = load_config()
        for key, want in frame.expect_value.items():
            assert getattr(config, key) == want, (frame.id, key)
        return

    root = make_project(tmp_path, frame.files)
    gw = seed_gateway(frame.cloud) if frame.inject_gateway else None

    def fake_input(prompt=""):
        print(prompt, end="")             # real input() echoes the prompt
        if frame.stdin == RAISE_EOF:
            raise EOFError
        if frame.stdin == RAISE_KI:
            raise KeyboardInterrupt
        return frame.stdin

    if frame.stdin is not None:
        monkeypatch.setattr("builtins.input", fake_input)
    else:   # a prompt here would hang real runs -- fail loudly instead
        monkeypatch.setattr("builtins.input",
                            lambda *_: pytest.fail(f"{frame.id}: unexpected prompt"))

    for key, value in (frame.env or {}).items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    if frame.chdir:
        monkeypatch.chdir(root)

    args = list(frame.argv or [])
    if not frame.raw_argv and "--project" not in args:
        args[1:1] = ["--project", str(root)]
    rc = main(args, gateway=gw)
    assert rc == frame.expect_rc, frame.id

    captured = capsys.readouterr()
    for sub in frame.expect_out:
        assert sub in captured.out, (frame.id, sub)
    for sub in frame.expect_out_absent:
        assert sub not in captured.out, (frame.id, sub)
    for sub in frame.expect_err:
        assert sub in captured.err, (frame.id, sub)
    if frame.expect_json is not None:
        # a confirmation prompt may precede the JSON on stdout (real
        # input() echoes it) -- parse from the first opening brace
        data = json.loads(captured.out[captured.out.index("{"):])
        for key, want in frame.expect_json.items():
            assert data[key] == want, (frame.id, key)
    if frame.inject_gateway:
        if frame.expect_call_log is not None:
            assert gw.call_log == frame.expect_call_log, (frame.id, gw.call_log)
        check_cloud(gw, frame.expect_cloud)
    for rel in frame.expect_files:
        assert (root / rel).exists(), (frame.id, rel)
