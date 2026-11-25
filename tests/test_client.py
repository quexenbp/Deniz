from __future__ import annotations

from pathlib import Path

from deniz.client import Client
from deniz.kit.server import start_background
from tests.test_server import parts


def test_client_roundtrip(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, token="t")
    port = server.server_address[1]
    try:
        with Client(f"http://127.0.0.1:{port}", "t") as client:
            assert client.health()["ok"] is True
            case = client.create_case("sdk-case", allow=["example.com"])
            monitor = client.add_monitor(case["id"], "identity", "alice", 30)
            assert monitor["target"] == "alice"
            assert client.cases()[0]["name"] == "sdk-case"
            assert client.stats()["cases"] == 1
            assert client.export_case(case["id"])["path"].endswith(".zip")
    finally:
        server.shutdown()
        server.server_close()


def test_client_cursor_pages(tmp_path: Path) -> None:
    server, _ = start_background(**parts(tmp_path), port=0, token="t")
    port = server.server_address[1]
    try:
        with Client(f"http://127.0.0.1:{port}", "t") as client:
            for name in ("a", "b", "c"):
                client.create_case(name)

            first = client.cases_page(limit=1)
            assert first.total == 3
            assert first.offset == 0
            assert len(first.items) == 1
            assert first.next_cursor

            second = client.cases_page(limit=1, cursor=first.next_cursor)
            assert second.total == 3
            assert second.offset == 1
            assert second.items[0]["id"] != first.items[0]["id"]

            seen = {item["id"] for item in client.cases(limit=100)}
            assert len(seen) == 3
            assert client.runs() == []
    finally:
        server.shutdown()
        server.server_close()
