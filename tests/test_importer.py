from __future__ import annotations

from pathlib import Path

from deniz.kit.graph import GraphStore
from deniz.kit.importer import parse_lines, parse_nmap_xml, run_import
from deniz.kit.store import RunStore


def test_parse_filters_and_normalises() -> None:
    items = parse_lines("hostname", ["# comment", "A.Example.COM", "*.b.example.com", "bad host", "a.example.com", ""])
    assert [i.value for i in items] == ["a.example.com", "b.example.com"]


def test_parse_url_and_ip() -> None:
    assert parse_lines("ip", ["192.0.2.1", "nope"])[0].value == "192.0.2.1"
    assert parse_lines("url", ["https://a.test/x"])[0].value == "https://a.test/x"


def test_run_import_writes(tmp_path: Path) -> None:
    runs = RunStore(tmp_path / "runs")
    graph = GraphStore(tmp_path / "g.sqlite3")
    result = run_import("hostname", ["a.test", "b.test"], case_id="c", source_url="file://x", runs=runs, graph=graph)
    assert len(result.items) == 2
    assert graph.stats()["entities"] >= 2
    assert (tmp_path / "runs").exists()


NMAP = """<?xml version="1.0"?>
<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/>
<hostnames><hostname name="a.test"/></hostnames>
<ports>
<port portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port>
<port portid="22"><state state="closed"/></port>
</ports></host></nmaprun>"""


def test_nmap_parse() -> None:
    items = parse_nmap_xml(NMAP)
    assert {i.type for i in items} == {"hostname", "ip", "service"}
    service = next(i for i in items if i.type == "service")
    assert service.value == "a.test:443"
    assert service.attrs["tls"] is True
    assert service.attrs["product"] == "nginx"
