import json

import pytest

from strato.core.models import InventoryRecord
from strato.services.ebs.domains.inventory.views import EBSInventoryView


@pytest.fixture
def inventory_result():
    return InventoryRecord(
        account_id="123",
        region="us-east-1",
        resource_name="db-data",
        resource_arn="arn:aws:ec2:us-east-1:123:volume/vol-abc",
        details={
            "VolumeId": "vol-abc",
            "VolumeType": "gp2",
            "SizeGB": 500,
            "Iops": 1500,
            "Throughput": 0,
            "CreateDate": "2025-02-01T00:00:00",
            "AvailabilityZone": "us-east-1a",
            "Encrypted": True,
            "KmsKeyAlias": "alias/aws/ebs",
            "AttachedInstances": ["i-01", "i-02"],
            "InstanceStates": ["running", "stopped"],
            "State": "in-use",
            "SnapshotCount": 5,
            "UtilizationPct30d": 85.5,
            "LastAccessed": "2025-02-15",
            "TotalMonthlyCost": 50.0,
            "RightSizingRecommendation": "Modify",
            "Tags": {"Name": "db-data", "Env": "Prod"},
        },
    )


def test_get_headers():
    headers = EBSInventoryView.get_headers("INVENTORY")
    # Terminal headers
    assert "Volume ID" in headers
    assert "State" in headers
    assert "Monthly Cost" in headers
    assert len(headers) == 8


def test_format_row(inventory_result):
    row = EBSInventoryView.format_row(inventory_result)

    # Testing the short terminal output
    assert row[0] == "123"  # Account ID
    assert row[1] == "us-east-1"  # Region
    assert row[2] == "vol-abc"  # Volume ID
    assert row[3] == "gp2"  # Type
    assert row[4] == "500"  # Size
    assert row[5] == "in-use"  # State
    assert row[6] == "2 instance(s)"  # Attached Instances display
    assert row[7] == "$50.00"  # Monthly Cost display


def test_format_csv_row(inventory_result):
    row = EBSInventoryView.format_csv_row(inventory_result)

    # Testing the exhaustive CSV output mapping
    assert row[0] == "123"
    assert row[2] == "db-data"
    assert row[3] == "vol-abc"
    assert row[4] == "arn:aws:ec2:us-east-1:123:volume/vol-abc"
    assert row[5] == "gp2"
    assert row[6] == "500"
    assert row[13] == "alias/aws/ebs"
    assert row[14] == "i-01;i-02"
    assert row[15] == "running;stopped"
    assert row[16] == "5"
    assert row[17] == "85.5"
    assert row[19] == "50.0"

    assert json.loads(row[21]) == {"Name": "db-data", "Env": "Prod"}
