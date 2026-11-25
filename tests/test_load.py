from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

from deniz.kit.cases import CaseStore
from deniz.kit.graph import GraphStore
from deniz.kit.models import Observation, Result, Source, Target
from deniz.kit.server import start_background
from tests.test_server import parts

pytestmark = pytest.mark.load


def test_case_store_bulk(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "cases.sqlite3")
    started = time.perf_counter()
    for index in range(400):
        store.create(f"case-{index}")
    elapsed = time.perf_counter() - started
    assert len(store.list_cases()) == 400
    assert elapsed < 20


def test_graph_soak(tmp_path: Path) -> None:
    graph = GraphStore(tmp_path / "g.sqlite3")
    result = Result(module="load", target=Target(type="domain", value="example.com"))
    source = Source(provider="load", url="https://example.test")
    for index in range(1500):
        result.add(Observation(type="hostname", value=f"h{index}.example.com", sources=[source]))
    started = time.perf_counter()
    graph.record(result)
    elapsed = time.perf_counter() - started
    assert graph.stats()["observations"] == 1500
    assert elapsed < 20


def test_parallel_api_reads(tmp_path: Path) -> None:
    stores = parts(tmp_path)
    stores["cases"].create("load")
    server, _ = start_background(**stores, port=0, token="t", limit_per_second=1000, limit_burst=1000)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"
    headers = {"authorization": "Bearer t"}
    try:

        def read(_: int) -> int:
            return httpx.get(f"{base}/api/cases?limit=10", headers=headers, timeout=10).status_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(read, range(96)))
        assert codes == [200] * 96
    finally:
        server.shutdown()
        server.server_close()
