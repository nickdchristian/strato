from datetime import UTC, datetime, timedelta

from strato.services.ebs.domains.inventory.checks import (
    EBSInventoryResult,
    EBSInventoryScanner,
)


def test_result_serialization():
    result = EBSInventoryResult(
        resource_id="vol-123",
        resource_name="data-vol",
        resource_arn="arn:aws:ec2:us-east-1:123:volume/vol-123",
        region="us-east-1",
        account_id="123",
        create_date=datetime(2025, 1, 1, tzinfo=UTC),
        attached_resources=["i-1", "i-2"],
    )

    data = result.to_dict()

    assert data["create_date"] == "2025-01-01T00:00:00+00:00"
    assert "findings" not in data
    assert "status" not in data
    assert data["attached_resources"] == ["i-1", "i-2"]
    assert data["resource_arn"] == "arn:aws:ec2:us-east-1:123:volume/vol-123"


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ebs.domains.inventory.checks.EBSClient"
    )
    mock_client = mock_client_cls.return_value

    mock_client.check_optimizer_enrollment.return_value = "Active"
    mock_client.get_volume_metrics.return_value = {
        "VolumeIdleTime": 0.0,
        "VolumeReadOps": 100.0,
        "VolumeWriteOps": 50.0,
    }
    mock_client.get_kms_alias.return_value = "alias/my-kms-key"

    scanner = EBSInventoryScanner(
        check_type="ALL", session=mocker.Mock(), account_id="123"
    )
    scanner.optimizer_status = "Active"

    scanner.instance_map = {"i-12345": "running"}
    scanner.snapshot_map = {"vol-123": [{"SnapshotId": "snap-1"}]}
    scanner.recommendations = {
        "arn:aws:ec2:us-east-1:123:volume/vol-123": {"finding": "NotOptimized"}
    }

    volume_data = {
        "VolumeId": "vol-123",
        "Region": "us-east-1",
        "VolumeType": "gp3",
        "Size": 100,
        "Iops": 3000,
        "Throughput": 125,
        "State": "in-use",
        "Encrypted": True,
        "KmsKeyId": "key-abc",
        "CreateTime": datetime(2025, 1, 1, tzinfo=UTC),
        "Attachments": [{"InstanceId": "i-12345"}],
        "Tags": [{"Key": "Name", "Value": "ProdDatabase"}],
    }

    result = scanner.analyze_resource(volume_data)

    assert isinstance(result, EBSInventoryResult)
    assert result.resource_name == "ProdDatabase"
    assert result.resource_id == "vol-123"
    assert result.region == "us-east-1"

    assert result.type == "gp3"
    assert result.size == 100
    assert result.total_monthly_cost == 8.0

    assert result.encrypted is True
    assert result.kms_key_alias == "alias/my-kms-key"

    assert result.attached_resources == ["i-12345"]
    assert result.instance_states == ["running"]

    assert result.snapshot_count == 1
    assert result.right_sizing_recommendation == "NotOptimized"

    assert result.unused_volume_flag is False


def test_scanner_unused_and_overprovisioned(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ebs.domains.inventory.checks.EBSClient"
    )
    mock_client = mock_client_cls.return_value
    mock_client.get_volume_metrics.return_value = {"VolumeIdleTime": 86400.0 * 30}

    scanner = EBSInventoryScanner(
        check_type="ALL", session=mocker.Mock(), account_id="123"
    )

    volume_data = {
        "VolumeId": "vol-idle",
        "Region": "us-east-1",
        "Size": 50,
        "CreateTime": datetime.now(UTC) - timedelta(days=35),
        "Attachments": [],
    }

    result = scanner.analyze_resource(volume_data)

    assert result.unused_volume_flag is True
    assert result.utilization_percentage_30_days == 0.0
