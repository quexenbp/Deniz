"""Import host, URL, IP and identity lists into a case.

Input is line-based; ``#`` and blank lines are ignored. Values are validated
and normalised with the same models as live collection.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .graph import GraphStore
from .models import Observation, Result, Source, Target
from .store import RunStore
from .util import normalize_hostname

KINDS = {
    "hostname": "hostname",
    "url": "url",
    "ip": "ip",
    "email": "email",
    "username": "username",
}


def parse_lines(kind: str, lines: list[str], source_url: str = "file://import") -> list[Observation]:
    if kind not in KINDS:
        raise ValueError(f"unknown import kind: {kind}")
    obs_type = KINDS[kind]
    seen: set[str] = set()
    out: list[Observation] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value = line
        if kind == "hostname":
            value = normalize_hostname(line) or ""
        elif kind == "ip":
            try:
                Target(type="ip", value=line)
            except ValueError:
                continue
            value = line
        elif kind == "url":
            value = line
        elif kind == "email":
            value = line.lower()
        elif kind == "username":
            value = line.strip().lstrip("@")
        try:
            target = Target(type=kind, value=value)  # type: ignore[arg-type]
        except ValueError:
            continue
        if target.value in seen:
            continue
        seen.add(target.value)
        out.append(
            Observation(
                type=obs_type,  # type: ignore[arg-type]
                value=target.value,
                confidence=0.8,
                sources=[Source(provider="import", url=source_url)],
                attrs={"imported": True},
            )
        )
    return out


def run_import(
    kind: str,
    lines: list[str],
    *,
    case_id: str,
    source_url: str,
    runs: RunStore,
    graph: GraphStore,
) -> Result:
    observations = parse_lines(kind, lines, source_url)
    first = observations[0].value if observations else "import"
    target_type = kind
    result = Result(schema="deniz.result/1", module=f"import.{kind}", provider="import",
                    target=Target(type=target_type, value=first))  # type: ignore[arg-type]
    for obs in observations:
        result.add(obs)
    run = runs.begin(f"import-{kind}")
    result.run_id = run.run_id
    runs.write(run, result)
    graph.record(result)
    return result


def parse_nmap_xml(text: str, source_url: str = "file://nmap.xml") -> list[Observation]:
    root = ET.fromstring(text)
    source = [Source(provider="import", url=source_url)]
    out: list[Observation] = []
    for host in root.iter("host"):
        addresses = [a.get("addr", "") for a in host.findall("address")]
        addresses = [a for a in addresses if a]
        names = [normalize_hostname(h.get("name", "")) for h in host.findall("hostnames/hostname")]
        names = [n for n in names if n]
        host_label = names[0] if names else (addresses[0] if addresses else "")
        for name in dict.fromkeys(names):
            out.append(Observation(type="hostname", value=name, confidence=0.95, sources=source, attrs={"imported": True}))
        for address in dict.fromkeys(addresses):
            out.append(Observation(type="ip", value=address, confidence=0.95, sources=source, attrs={"host": host_label, "imported": True}))
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = int(port.get("portid", "0"))
            service = port.find("service")
            attrs = {"port": number, "host": host_label, "imported": True, "tls": number in (443, 8443)}
            if service is not None:
                attrs["service"] = service.get("name")
                attrs["product"] = service.get("product")
                attrs["version"] = service.get("version")
            out.append(Observation(type="service", value=f"{host_label}:{number}", confidence=0.95, sources=source, attrs=attrs))
    return out


def run_import_nmap(text: str, *, source_url: str, runs: RunStore, graph: GraphStore) -> Result:
    observations = parse_nmap_xml(text, source_url)
    hostname_obs = next((o for o in observations if o.type == "hostname"), None)
    ip_obs = next((o for o in observations if o.type == "ip"), None)
    if hostname_obs:
        target = Target(type="hostname", value=hostname_obs.value)
    elif ip_obs:
        target = Target(type="ip", value=ip_obs.value)
    else:
        raise ValueError("nmap file contains no hosts")
    result = Result(schema="deniz.result/1", module="import.nmap", provider="import", target=target)
    for obs in observations:
        result.add(obs)
    run = runs.begin("import-nmap")
    result.run_id = run.run_id
    runs.write(run, result)
    graph.record(result)
    return result
