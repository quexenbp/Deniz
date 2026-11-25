"""Cluster text lines by token similarity (offline, stdlib only).

Input is one document per line. Lines whose Jaccard similarity reaches the
threshold are merged into a cluster. This is a cheap triage aid, not a
statistical model.
"""

from __future__ import annotations

import re
from collections import Counter

from ..errors import ParseChanged
from ..models import Observation, Source, Target
from ..util import clip
from .base import Context, Provider, ProviderInfo

TOKEN = re.compile(r"[a-z0-9][a-z0-9_-]{2,}")
STOP = frozenset(
    ["the", "and", "for", "with", "from", "that", "this", "into", "over", "under", "about", "after", "before", "than", "then", "they", "them", "their", "there", "here", "was", "were", "are", "you", "your", "our", "its", "his", "her", "not", "but", "all", "any", "can", "could", "should", "would", "will", "just", "also", "more", "most"]
)
MAX_LINES = 200
THRESHOLD = 0.3


def tokenize(line: str) -> set[str]:
    return {t for t in TOKEN.findall(line.lower()) if t not in STOP}


class Cluster(Provider):
    info = ProviderInfo(
        name="cluster",
        title="Line clustering",
        capabilities=frozenset({"analysis"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        notes="Offline Jaccard clustering of newline-separated text; max 200 lines.",
    )
    cache_ttl = 86400.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "text":
            raise ParseChanged("cluster expects a text target with one document per line")
        lines = [line.strip() for line in target.value.splitlines() if line.strip()][:MAX_LINES]
        if not lines:
            raise ParseChanged("no non-empty lines")

        tokens = [tokenize(line) for line in lines]
        parent = list(range(len(lines)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for i in range(len(lines)):
            if not tokens[i]:
                continue
            for j in range(i + 1, len(lines)):
                if not tokens[j]:
                    continue
                overlap = len(tokens[i] & tokens[j])
                if overlap and overlap / len(tokens[i] | tokens[j]) >= THRESHOLD:
                    union(i, j)

        groups: dict[int, list[int]] = {}
        for index in range(len(lines)):
            groups.setdefault(find(index), []).append(index)

        out: list[Observation] = []
        for order, members in enumerate(sorted(groups.values(), key=lambda m: (-len(m), m[0]))):
            if len(members) < 2:
                continue
            terms = Counter(term for index in members for term in tokens[index]).most_common(5)
            out.append(
                Observation(
                    type="note",
                    value=f"cluster {order}: {len(members)} lines — {clip(lines[members[0]], 120)}",
                    confidence=0.6,
                    sources=[Source(provider=self.info.name, url="local://cluster")],
                    attrs={
                        "record": "CLUSTER",
                        "cluster": order,
                        "size": len(members),
                        "terms": [term for term, _ in terms],
                        "members": [{"index": index, "text": clip(lines[index], 240)} for index in members[:20]],
                    },
                )
            )
        if not out:
            raise ParseChanged("no lines shared enough terms")
        return out
