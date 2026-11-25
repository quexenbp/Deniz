FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DENIZ_HOME=/data

RUN useradd --create-home --uid 10001 deniz && mkdir -p /data && chown deniz:deniz /data
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY deniz ./deniz

RUN pip install --upgrade pip && pip install . && chown -R deniz:deniz /app

USER deniz
VOLUME ["/data"]
ENTRYPOINT ["deniz"]
CMD ["doctor"]

FROM base AS test
USER root
RUN pip install ".[dev]"
COPY tests ./tests
USER deniz
RUN python -m pytest -q

FROM base AS pdf
USER root
RUN pip install playwright && playwright install --with-deps chromium
USER deniz

FROM pdf AS browser
