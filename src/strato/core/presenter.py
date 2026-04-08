import csv
import json
import sys
from typing import Any, Protocol

from rich.console import Console
from rich.table import Table

from strato.core.models import InventoryRecord

console_out = Console(file=sys.stdout)
console_err = Console(stderr=True)


class ViewProtocol(Protocol):
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]: ...

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]: ...

    @classmethod
    def format_row(cls, result: Any) -> list[str]: ...

    @classmethod
    def format_csv_row(cls, result: Any) -> list[str]: ...


class GenericView:
    @classmethod
    def get_headers(cls, check_type: str) -> list[str]:
        return ["Account ID", "Resource", "Region", "Details"]

    @classmethod
    def get_csv_headers(cls, check_type: str) -> list[str]:
        return cls.get_headers(check_type)

    @classmethod
    def format_row(cls, result: InventoryRecord) -> list[str]:
        # Truncate details for the terminal table so it doesn't blow up the UI
        details_str = json.dumps(result.details)
        if len(details_str) > 50:
            details_str = details_str[:47] + "..."

        return [
            result.account_id,
            result.resource_name,
            result.region,
            details_str,
        ]

    @classmethod
    def format_csv_row(cls, result: InventoryRecord) -> list[str]:
        return [
            result.account_id,
            result.resource_name,
            result.region,
            json.dumps(result.details),
        ]


class InventoryPresenter:
    def __init__(
        self,
        results: list[InventoryRecord],
        check_type: str = "ALL",
        view_class: type[ViewProtocol] = GenericView,
    ):
        self.results = results
        self.check_type = check_type
        self.view_class = view_class or GenericView

    def print_json(self):
        console_out.print_json(data=[r.to_dict() for r in self.results])

    def print_csv(self):
        writer = csv.writer(sys.stdout)
        headers = self.view_class.get_csv_headers(self.check_type)
        writer.writerow(headers)

        for result in self.results:
            writer.writerow(self.view_class.format_csv_row(result))

    def print_table(self, title: str):
        table = Table(title=title, show_lines=True)
        headers = self.view_class.get_headers(self.check_type)

        for header in headers:
            table.add_column(header)

        for result in self.results:
            table.add_row(*self.view_class.format_row(result))

        console_out.print(table)
        self._print_summary()

    def _print_summary(self):
        count = len(self.results)
        console_err.print(
            f"\n[bold blue]Discovered {count} total resources.[/bold blue]"
        )
