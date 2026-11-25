from __future__ import annotations

import socket
from pathlib import Path

from deniz.kit.cli import main


def test_doctor_reports_proxy(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("DENIZ_HOME", str(tmp_path))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    monkeypatch.setenv("DENIZ_PROXY", f"socks5h://127.0.0.1:{port}")
    try:
        code = main(["doctor"])
    finally:
        listener.close()
    out = capsys.readouterr().out
    assert code == 0
    assert "proxy" in out
    assert "FAIL" not in out
    assert f"127.0.0.1:{port}" in out
