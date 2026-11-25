"""Optional Textual TUI.

Install with ``pip install 'deniz[tui]'`` then ``deniz tui``.
"""

from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane

from .cli import _runtime
from .findings import Finding
from .providers.registry import Registry


class DenizApp(App):
    TITLE = "Deniz"
    SUB_TITLE = "read-only console"
    BINDINGS: ClassVar = [("q", "quit", "quit"), ("r", "refresh", "refresh")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static("", id="stats")
            with TabbedContent():
                with TabPane("Cases", id="cases"):
                    yield DataTable(id="cases-table")
                with TabPane("Alerts", id="alerts"):
                    yield DataTable(id="alerts-table")
                with TabPane("Findings", id="findings"):
                    yield DataTable(id="findings-table")
                with TabPane("Providers", id="providers"):
                    yield DataTable(id="providers-table")
        yield Footer()

    def on_mount(self) -> None:
        for table_id, columns in {
            "cases-table": ("id", "name", "runs", "updated"),
            "alerts-table": ("id", "kind", "summary"),
            "findings-table": ("severity", "title", "acked"),
            "providers-table": ("provider", "capabilities", "health"),
        }.items():
            table = self.query_one(f"#{table_id}", DataTable)
            table.add_columns(*columns)
            table.cursor_type = "row"
        self.refresh_data()

    def refresh_data(self) -> None:
        rt = _runtime()
        cases = rt.cases.list_cases(include_archived=True)
        alerts = rt.monitors.alerts(include_acked=False, limit=200)
        findings: list[tuple[str, Finding]] = []
        for case in cases:
            findings.extend((case.name, f) for f in rt.findings.list(case.id, include_acked=False))
        stats = rt.graph.stats()

        self.query_one("#stats", Static).update(
            f"cases {len(cases)} · open alerts {len(alerts)} · open findings {len(findings)} · "
            f"entities {stats['entities']}"
        )
        case_table = self.query_one("#cases-table", DataTable)
        case_table.clear()
        for case in cases:
            case_table.add_row(case.id[:10], case.name, str(len(case.runs)), case.updated_at[:19])

        alert_table = self.query_one("#alerts-table", DataTable)
        alert_table.clear()
        for alert in alerts:
            alert_table.add_row(alert["id"][:10], alert["kind"], alert["summary"])

        finding_table = self.query_one("#findings-table", DataTable)
        finding_table.clear()
        for case_name, finding in findings:
            finding_table.add_row(finding.severity_override or finding.severity, f"[{case_name}] {finding.title}", "yes" if finding.acked else "no")

        provider_table = self.query_one("#providers-table", DataTable)
        provider_table.clear()
        for info in Registry().infos():
            score = rt.health.score(info.name)
            provider_table.add_row(info.name, ",".join(sorted(info.capabilities)), "unknown" if score is None else f"{score:.0%}")
        rt.client.close()

    def action_refresh(self) -> None:
        self.refresh_data()
        self.notify("refreshed")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "alerts-table":
            return
        row = event.data_table.get_row_at(event.cursor_row)
        if not row:
            return
        rt = _runtime()
        try:
            rt.monitors.ack(str(row[0]))
        finally:
            rt.client.close()
        self.refresh_data()
        self.notify("alert acknowledged")


def run() -> int:
    DenizApp().run()
    return 0
