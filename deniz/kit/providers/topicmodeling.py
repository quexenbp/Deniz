"""TF-IDF top terms per line and per corpus (offline, stdlib only)."""

from __future__ import annotations

import math
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
TOP = 5


def terms(line: str) -> Counter:
    return Counter(t for t in TOKEN.findall(line.lower()) if t not in STOP)


class TopicModeling(Provider):
    info = ProviderInfo(
        name="topicmodeling",
        title="TF-IDF topic terms",
        capabilities=frozenset({"analysis"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        notes="Offline TF-IDF over newline-separated text; max 200 lines.",
    )
    cache_ttl = 86400.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "text":
            raise ParseChanged("topicmodeling expects a text target with one document per line")
        lines = [line.strip() for line in target.value.splitlines() if line.strip()][:MAX_LINES]
        if not lines:
            raise ParseChanged("no non-empty lines")

        docs = [terms(line) for line in lines]
        total = len(docs)
        document_frequency: Counter = Counter()
        for doc in docs:
            document_frequency.update(doc.keys())

        def weight(term: str, count: int) -> float:
            idf = math.log((1 + total) / (1 + document_frequency[term])) + 1.0
            return count * idf

        source = [Source(provider=self.info.name, url="local://tfidf")]
        out: list[Observation] = []
        corpus: Counter = Counter()
        for index, doc in enumerate(docs):
            if not doc:
                continue
            scored = sorted(((weight(term, count), term) for term, count in doc.items()), reverse=True)[:TOP]
            picked = [term for _, term in scored]
            corpus.update({term: int(score * 100) for score, term in scored})
            out.append(
                Observation(
                    type="note",
                    value=f"line {index + 1}: {', '.join(picked)}",
                    confidence=0.5,
                    sources=source,
                    attrs={"record": "TOPIC", "index": index, "terms": picked, "text": clip(lines[index], 240)},
                )
            )
        if corpus:
            top = [term for term, _ in corpus.most_common(TOP * 2)]
            out.append(
                Observation(
                    type="note",
                    value="corpus: " + ", ".join(top),
                    confidence=0.5,
                    sources=source,
                    attrs={"record": "TOPIC_GLOBAL", "terms": top},
                )
            )
        if not out:
            raise ParseChanged("no terms found")
        return out
