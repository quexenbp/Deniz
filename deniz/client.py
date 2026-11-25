"""Small Python client for the Deniz HTTP API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class Page:
    """One page plus the token for the next one."""

    items: list[Any]
    total: int | None = None
    offset: int | None = None
    next_cursor: str | None = None


class Client:
    def __init__(self, base_url: str = "http://127.0.0.1:8787", token: str | None = None, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self.token}"} if self.token else {}

    def _get(self, path: str, **params: Any) -> Any:
        resp = self._client.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()

    def _get_page(self, path: str, **params: Any) -> Page:
        resp = self._client.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
        resp.raise_for_status()
        total = resp.headers.get("x-total-count")
        offset = resp.headers.get("x-offset")
        return Page(
            items=resp.json(),
            total=int(total) if total is not None else None,
            offset=int(offset) if offset is not None else None,
            next_cursor=resp.headers.get("x-next-cursor") or None,
        )

    def _post(self, path: str, body: dict | None = None) -> Any:
        resp = self._client.post(f"{self.base_url}{path}", headers=self._headers(), json=body or {})
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict:
        return self._get("/health")

    def stats(self) -> dict:
        return self._get("/api/stats")

    def providers(self) -> list[dict]:
        return self._get("/api/providers")

    def cases_page(
        self,
        include_archived: bool = False,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> Page:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if include_archived:
            params["archived"] = ""
        if cursor:
            params["cursor"] = cursor
        return self._get_page("/api/cases", **params)

    def cases(
        self,
        include_archived: bool = False,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> list[dict]:
        return self.cases_page(include_archived, limit, offset, cursor).items

    def case(self, case_id: str) -> dict:
        return self._get(f"/api/cases/{case_id}")

    def create_case(self, name: str, allow: list[str] | None = None, deny: list[str] | None = None) -> dict:
        return self._post("/api/cases", {"name": name, "allow": allow or [], "deny": deny or []})

    def add_monitor(self, case_id: str, kind: str, target: str, every: int = 60) -> dict:
        return self._post("/api/monitor", {"case": case_id, "kind": kind, "target": target, "every": every})

    def run_monitor(self, monitor_id: str) -> dict:
        return self._post(f"/api/monitor/{monitor_id}/run")

    def alerts_page(
        self,
        include_acked: bool = False,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> Page:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if include_acked:
            params["acked"] = ""
        if cursor:
            params["cursor"] = cursor
        return self._get_page("/api/alerts", **params)

    def alerts(
        self,
        include_acked: bool = False,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> list[dict]:
        return self.alerts_page(include_acked, limit, offset, cursor).items

    def ack_all(self) -> dict:
        return self._post("/api/alerts/ack", {"all": True})

    def findings_page(
        self,
        case_id: str,
        include_acked: bool = False,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> Page:
        params: dict[str, Any] = {"case": case_id, "limit": limit, "offset": offset}
        if include_acked:
            params["acked"] = ""
        if cursor:
            params["cursor"] = cursor
        return self._get_page("/api/findings", **params)

    def findings(
        self,
        case_id: str,
        include_acked: bool = False,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> list[dict]:
        return self.findings_page(case_id, include_acked, limit, offset, cursor).items

    def export_case(self, case_id: str) -> dict:
        return self._post(f"/api/cases/{case_id}/export")

    def run_report(self, run_id: str) -> dict:
        return self._post(f"/api/runs/{run_id}/report")

    def runs_page(self, limit: int = 20, offset: int = 0, cursor: str | None = None) -> Page:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor:
            params["cursor"] = cursor
        return self._get_page("/api/runs", **params)

    def runs(self, limit: int = 20, offset: int = 0, cursor: str | None = None) -> list[str]:
        return self.runs_page(limit, offset, cursor).items

    def run(self, run_id: str) -> dict:
        return self._get(f"/api/runs/{run_id}")

    def graph(self, value: str) -> dict:
        return self._get(f"/api/graph/{value}")
