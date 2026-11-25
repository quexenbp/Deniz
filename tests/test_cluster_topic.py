from __future__ import annotations

from pathlib import Path

import httpx

from deniz.kit.auth import AuthStore
from deniz.kit.cache import Cache
from deniz.kit.http import HttpClient
from deniz.kit.models import Target
from deniz.kit.providers.base import Context
from deniz.kit.providers.cluster import Cluster, tokenize
from deniz.kit.providers.topicmodeling import TopicModeling
from deniz.kit.ratelimit import Limiter
from deniz.kit.scope import Scope


def ctx(tmp_path: Path) -> Context:
    client = HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter(), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    return Context(http=client, scope=Scope(), auth=AuthStore(tmp_path / "p.toml"))


TEXT = "\n".join(
    [
        "nginx reverse proxy misconfiguration leaks internal hostnames",
        "reverse proxy nginx leaks internal hostnames via headers",
        "kubernetes ingress controller exposes dashboard without auth",
        "kubernetes dashboard exposed without authentication on ingress",
        "unrelated note about javascript bundlers and tree shaking",
    ]
)


def test_tokenize_strips_stopwords() -> None:
    tokens = tokenize("The reverse proxy for the internal hostnames")
    assert "reverse" in tokens and "the" not in tokens and "for" not in tokens


def test_cluster_groups_overlap(tmp_path: Path) -> None:
    items = Cluster(HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())).run(
        Target(type="text", value=TEXT), ctx(tmp_path)
    )
    sizes = sorted(i.attrs["size"] for i in items)
    assert sizes == [2, 2]
    assert all(i.attrs["record"] == "CLUSTER" for i in items)


def test_cluster_needs_overlap(tmp_path: Path) -> None:
    text = "alpha beta gamma\nalpha beta gamma\ndelta epsilon zeta"
    items = Cluster(HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())).run(
        Target(type="text", value=text), ctx(tmp_path)
    )
    assert len(items) == 1
    assert items[0].attrs["size"] == 2


def test_topicmodeling_terms(tmp_path: Path) -> None:
    items = TopicModeling(HttpClient(Cache(tmp_path / "c.sqlite3"), Limiter())).run(
        Target(type="text", value=TEXT), ctx(tmp_path)
    )
    assert any(i.attrs["record"] == "TOPIC_GLOBAL" for i in items)
    first = next(i for i in items if i.attrs["record"] == "TOPIC")
    assert first.attrs["terms"]
