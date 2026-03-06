from datetime import datetime

import pytest

from strato.services.ebs.domains.inventory.checks import EBSInventoryResult
from strato.services.ebs.domains.inventory.views import EBSInventoryView


@pytest.fixture
def inventory_result():
    return EBSInventoryResult(
        account_id="123",
        region="us-east-1",
        resource_name="db-data",
        resource_arn="arn:aws:ec2:us-east-1:123:volume/vol-123",
        attached_resources=["i-01", "i-02"],
        instance_states=["running", "stopped"],
        volume_id="vol-abc",
        type="gp2",
        size=500,
        iops=1500,
        throughput=None,
        create_date=datetime(2025, 2, 1),
        availability_zone="us-east-1a",
        encrypted=True,
        kms_key_alias="alias/aws/ebs",
        total_monthly_cost=50.0,
        snapshot_count=5,
        utilization_percentage_30_days=85.5,
        last_accessed_date="2025-02-15",
        right_sizing_recommendation="Modify",
        unused_volume_flag=False,
        overprovisioned_flag=False,
    )


def test_get_headers():
    headers = EBSInventoryView.get_headers()
    assert "volume_id" in headers
    assert "utilization_percentage_30_days" in headers
    assert "right_sizing_recommendation" in headers
    assert len(headers) == 21


def test_format_row(inventory_result):
    row = EBSInventoryView.format_row(inventory_result)

    assert row[0] == "123"  # account_id
    assert row[2] == "db-data"  # name
    assert row[3] == "i-01;i-02"  # attached_resources
    assert row[4] == "running;stopped"  # instance_states
    assert row[5] == "vol-abc"  # volume_id
    assert row[6] == "gp2"  # type
    assert row[7] == "500"  # size
    assert "2025-02-01" in row[10]  # create_date
    assert row[12] == "True"  # encryption
    assert row[14] == "50.0"  # total_monthly_cost
    assert row[16] == "85.5"  # utilization_percentage_30_days
