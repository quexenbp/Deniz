from __future__ import annotations

import json

import httpx

from deniz.mcp import start_http_background


def rpc(client: httpx.Client, method: str, params: dict | None = None, session: str | None = None) -> httpx.Response:
    headers = {"accept": "application/json"}
    if session:
        headers["mcp-session-id"] = session
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, headers=headers)


def test_http_transport_and_sse_progress() -> None:
    server, _ = start_http_background()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with httpx.Client(base_url=base, timeout=10) as client:
            init = rpc(client, "initialize", {"protocolVersion": "2024-11-05"})
            assert init.status_code == 200
            session = init.headers["mcp-session-id"]
            assert init.json()["result"]["serverInfo"]["name"] == "deniz"

            tools = rpc(client, "tools/list", session=session)
            assert tools.status_code == 200
            assert any(tool["name"] == "deniz_providers" for tool in tools.json()["result"]["tools"])

            stream = client.post(
                "/mcp",
                headers={
                    "accept": "text/event-stream",
                    "mcp-session-id": session,
                    "content-type": "application/json",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "deniz_providers", "arguments": {}, "_meta": {"progressToken": "p1"}},
                },
            )
            assert stream.status_code == 200
            assert stream.headers["content-type"].startswith("text/event-stream")
            events = [json.loads(line[6:]) for line in stream.text.splitlines() if line.startswith("data: ")]
            assert events[0]["method"] == "notifications/progress"
            assert events[0]["params"]["progress"] == 0
            assert events[1]["result"]["isError"] is False
            assert events[-1]["params"]["progress"] == 1

            assert rpc(client, "tools/list", session="unknown").status_code == 404
            assert client.delete("/mcp", headers={"mcp-session-id": session}).status_code == 204
            assert rpc(client, "tools/list", session=session).status_code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_http_sse_get_and_auth(monkeypatch) -> None:
    monkeypatch.setenv("DENIZ_MCP_TOKEN", "s3cret")
    server, _ = start_http_background()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with httpx.Client(base_url=base, timeout=10) as client:
            assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
            ok = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                headers={"authorization": "Bearer s3cret", "accept": "application/json"},
            )
            assert ok.status_code == 200

            stream = client.get("/mcp", headers={"authorization": "Bearer s3cret"})
            assert stream.status_code == 200
            assert stream.headers["content-type"].startswith("text/event-stream")
            assert "event: endpoint" in stream.text
    finally:
        server.shutdown()
        server.server_close()
