import re
from io import StringIO

from rich.console import Console

from strato.core.models import BaseScanner, InventoryRecord
from strato.core.presenter import InventoryPresenter


class MockScanner(BaseScanner):
    @property
    def service_name(self) -> str:
        return "TestService"

    def fetch_resources(self):
        return ["res1", "res2", "res3"]

    def analyze_resource(self, resource):
        return InventoryRecord(
            resource_arn=f"arn:{resource}",
            resource_name=resource,
            region="us-east-1",
            account_id="123456789012",
            details={"mock_key": "mock_value"} if resource == "res2" else {},
        )


def test_base_scanner_threading():
    scanner = MockScanner()
    results = scanner.scan(silent=True)

    assert len(results) == 3
    assert isinstance(results[0], InventoryRecord)

    # Verify the specific details dictionary logic worked
    res2 = next(r for r in results if r.resource_name == "res2")
    assert res2.details.get("mock_key") == "mock_value"


def test_presenter_json(mocker):
    results = [
        InventoryRecord(
            "arn:1", "bucket1", "us-east-1", "123", details={"env": "prod"}
        ),
        InventoryRecord("arn:2", "bucket2", "us-east-1", "123", details={"env": "dev"}),
    ]

    string_buffer = StringIO()

    mock_console = Console(
        file=string_buffer, force_terminal=False, width=1000, no_color=True
    )
    mocker.patch("strato.core.presenter.console_out", mock_console)

    presenter = InventoryPresenter(results)
    presenter.print_json()

    output = string_buffer.getvalue()

    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    clean_output = ansi_escape.sub("", output)

    assert '"resource_name": "bucket1"' in clean_output
    assert '"env": "prod"' in clean_output
    assert '"env": "dev"' in clean_output


def test_presenter_csv(capsys):
    results = [
        InventoryRecord(
            "arn:1", "bucket1", "us-east-1", "Unknown", details={"key": "val"}
        )
    ]
    presenter = InventoryPresenter(results)
    presenter.print_csv()

    captured = capsys.readouterr()

    # Verify the generic CSV headers and formatted row
    assert "Account ID,Resource,Region,Details" in captured.out
    assert 'Unknown,bucket1,us-east-1,"{""key"": ""val""}"' in captured.out
