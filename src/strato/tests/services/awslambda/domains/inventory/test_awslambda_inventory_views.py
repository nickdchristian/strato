import json

import pytest

from strato.core.models import InventoryRecord
from strato.services.awslambda.domains.inventory.views import LambdaInventoryView


@pytest.fixture
def inventory_result():
    return InventoryRecord(
        resource_arn="arn:aws:lambda:us-east-1:123:function:my-func",
        resource_name="my-func",
        region="us-east-1",
        account_id="123",
        details={
            "Runtime": "python3.11",
            "Architecture": "x86_64",
            "PackageType": "Zip",
            "MemorySize": 128,
            "Timeout": 30,
            "State": "Active",
            "Aliases": ["prod", "dev"],
            "EnvironmentKeys": ["LOG_LEVEL"],
            "FunctionUrl": "https://foo",
            "UrlAuthType": "NONE",
            "Tags": {"Env": "Prod", "Team": "DevOps"},
        },
    )


def test_get_headers():
    headers = LambdaInventoryView.get_headers("INVENTORY")
    assert "Function Name" in headers
    assert "Runtime" in headers
    assert "Public URL" in headers


def test_format_csv_row(inventory_result):
    row = LambdaInventoryView.format_csv_row(inventory_result)

    assert row[0] == "123"
    assert row[1] == "us-east-1"
    assert row[2] == "my-func"
    assert row[3] == "arn:aws:lambda:us-east-1:123:function:my-func"
    assert row[4] == "python3.11"
    assert row[5] == "x86_64"
    assert row[7] == "128"
    assert row[8] == "30"

    assert row[10] == "prod, dev"
    assert row[11] == "LOG_LEVEL"
    assert row[12] == "https://foo"

    assert json.loads(row[14]) == {"Env": "Prod", "Team": "DevOps"}


def test_format_csv_row_empty_values():
    result = InventoryRecord(
        resource_arn="arn",
        resource_name="func",
        region="us-east-1",
        account_id="123",
        details={},
    )
    row = LambdaInventoryView.format_csv_row(result)

    # Missing numerical fields usually fall back to "" or are stringified None
    assert row[4] == ""  # Runtime
    assert row[7] == ""  # MemorySize
    assert row[10] == ""  # Aliases
    assert row[14] == "{}"  # Tags
