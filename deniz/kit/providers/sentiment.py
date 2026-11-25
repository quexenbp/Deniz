"""VADER sentiment over a text target."""

from __future__ import annotations

from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

from ..errors import ParseChanged
from ..models import Observation, Source, Target
from .base import Context, Provider, ProviderInfo


class Sentiment(Provider):
    info = ProviderInfo(
        name="sentiment",
        title="Sentiment analysis (VADER)",
        capabilities=frozenset({"analysis"}),
        auth="none",
        cost="free",
        rate=10.0,
        burst=5,
        notes="Offline lexicon; text target, English-biased.",
    )
    cache_ttl = 86400.0

    def run(self, target: Target, ctx: Context) -> list[Observation]:
        if target.type != "text":
            raise ParseChanged("sentiment expects a text target")
        analyzer = SentimentIntensityAnalyzer()
        scores = analyzer.polarity_scores(target.value)
        compound = scores["compound"]
        label = "positive" if compound >= 0.05 else "negative" if compound <= -0.05 else "neutral"
        return [
            Observation(
                type="note",
                value=f"{label} (compound {compound:+.2f})",
                confidence=0.7,
                sources=[Source(provider=self.info.name, url="local://vader")],
                attrs={
                    "record": "SENTIMENT",
                    "label": label,
                    "compound": compound,
                    "neg": scores["neg"],
                    "neu": scores["neu"],
                    "pos": scores["pos"],
                    "text": target.value[:1000],
                },
            )
        ]
