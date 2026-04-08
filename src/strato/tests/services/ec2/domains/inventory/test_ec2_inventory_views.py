import json

import pytest

from strato.core.models import InventoryRecord
from strato.services.ec2.domains.inventory.views import EC2InventoryView


@pytest.fixture
def inventory_result():
    return InventoryRecord(
        resource_arn="arn:aws:ec2:us-east-1:999:instance/i-123",
        resource_name="web-01",
        region="us-east-1",
        account_id="999",
        details={
            "InstanceType": "t3.micro",
            "State": "running",
            "AvailabilityZone": "us-east-1a",
            "PrivateIpAddress": "10.0.0.1",
            "PublicIpAddress": None,
            "LaunchTime": "2025-05-20T00:00:00",
            "Platform": "linux",
            "Architecture": "x86_64",
            "InstanceLifecycle": "on-demand",
            "ManagedBySSM": True,
            "HighestCpu14d": 50.5,
            "HighestMem14d": None,
            "SecurityGroupIds": ["sg-1", "sg-2"],
            "RightsizingRecommendation": "OptimizerDisabled",
            "Tags": {"Env": "Prod"},
        },
    )


def test_get_headers():
    headers = EC2InventoryView.get_headers()
    # Testing terminal headers
    assert "Instance ID" in headers
    assert "Type" in headers
    assert "State" in headers
    assert len(headers) == 8


def test_format_csv_row(inventory_result):
    row = EC2InventoryView.format_csv_row(inventory_result)

    assert row[0] == "999"  # Account ID
    assert row[2] == "web-01"  # Name
    assert row[3] == "i-123"  # ID from ARN
    assert row[4] == "arn:aws:ec2:us-east-1:999:instance/i-123"
    assert row[5] == "t3.micro"
    assert row[6] == "running"
    assert row[7] == "us-east-1a"
    assert row[9] == ""  # PublicIP was None
    assert "2025-05-20" in row[10]
    assert row[14] == "True"  # Managed by SSM
    assert row[22] == "50.5"  # CPU
    assert row[24] == ""  # Memory was None
    assert "sg-1;sg-2" in row[32]
    assert "OptimizerDisabled" in row[28]
    assert json.loads(row[-1]) == {"Env": "Prod"}
