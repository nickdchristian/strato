from datetime import UTC, datetime

from strato.core.models import InventoryRecord
from strato.services.ebs.domains.inventory.checks import EBSInventoryScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ebs.domains.inventory.checks.EBSClient"
    )
    mock_client = mock_client_cls.return_value

    mock_client.check_optimizer_enrollment.return_value = "Active"

    # Simulate a volume that has been completely idle
    mock_client.get_volume_metrics.return_value = {
        "VolumeIdleTime": 86400.0 * 30,  # 30 days of seconds
        "VolumeReadOps": 0.0,
        "VolumeWriteOps": 0.0,
    }
    mock_client.get_kms_alias.return_value = "alias/my-kms-key"

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = EBSInventoryScanner(
        check_type="ALL", session=mock_session, account_id="123"
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

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "ProdDatabase"
    assert result.resource_arn == "arn:aws:ec2:us-east-1:123:volume/vol-123"
    assert result.region == "us-east-1"

    d = result.details
    assert d["VolumeId"] == "vol-123"
    assert d["VolumeType"] == "gp3"
    assert d["SizeGB"] == 100
    assert d["TotalMonthlyCost"] == 8.0

    assert d["Encrypted"] is True
    assert d["KmsKeyAlias"] == "alias/my-kms-key"

    assert d["AttachedInstances"] == ["i-12345"]
    assert d["InstanceStates"] == ["running"]

    assert d["SnapshotCount"] == 1
    assert d["RightSizingRecommendation"] == "NotOptimized"

    # Because idle time was 30 days, utilization should be 0.0
    assert d["UtilizationPct30d"] == 0.0
    assert d["LastAccessed"] == "Unknown"
