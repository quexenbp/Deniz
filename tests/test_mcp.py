# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 quexenbp

from __future__ import annotations

from deniz.mcp import TOOLS, handle


def test_initialize() -> None:
    response = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
    assert response and response["result"]["serverInfo"]["name"] == "deniz"
    assert "tools" in response["result"]["capabilities"]


def test_tools_list_has_schemas() -> None:
    response = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {tool["name"] for tool in response["result"]["tools"]}
    assert names == {tool["name"] for tool in TOOLS}
    for tool in response["result"]["tools"]:
        assert tool["inputSchema"]["type"] == "object"


def test_unknown_method() -> None:
    response = handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})
    assert response and response["error"]["code"] == -32601


def test_unknown_tool_is_in_band_error() -> None:
    response = handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nope", "arguments": {}}})
    assert response and response["result"]["isError"] is True


def test_notification_returns_none() -> None:
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

