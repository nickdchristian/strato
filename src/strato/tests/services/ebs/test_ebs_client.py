import pytest

from strato.services.ebs.client import EBSClient


@pytest.fixture
def ebs_client_wrapper(mocker):
    mocker.patch("boto3.Session")
    return EBSClient()


def test_list_volumes(ebs_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"Volumes": [{"VolumeId": "vol-1"}, {"VolumeId": "vol-2"}]}
    ]

    ebs_client_wrapper._client.get_paginator.return_value = mock_paginator

    volumes = ebs_client_wrapper.list_volumes()
    assert len(volumes) == 2
    assert volumes[0]["VolumeId"] == "vol-1"


def test_get_all_snapshots(ebs_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {
            "Snapshots": [
                {"VolumeId": "vol-1", "SnapshotId": "snap-1"},
                {"VolumeId": "vol-1", "SnapshotId": "snap-2"},
                {"VolumeId": "vol-2", "SnapshotId": "snap-3"},
            ]
        }
    ]

    ebs_client_wrapper._client.get_paginator.return_value = mock_paginator

    snapshot_map = ebs_client_wrapper.get_all_snapshots()
    assert len(snapshot_map["vol-1"]) == 2
    assert len(snapshot_map["vol-2"]) == 1


def test_get_instance_states(ebs_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-1", "State": {"Name": "running"}},
                        {"InstanceId": "i-2", "State": {"Name": "stopped"}},
                    ]
                }
            ]
        }
    ]

    ebs_client_wrapper._client.get_paginator.return_value = mock_paginator

    states = ebs_client_wrapper.get_instance_states()
    assert states["i-1"] == "running"
    assert states["i-2"] == "stopped"


def test_get_kms_alias(ebs_client_wrapper, mocker):
    mock_paginator = mocker.Mock()
    mock_paginator.paginate.return_value = [
        {"Aliases": [{"AliasName": "alias/test-key", "TargetKeyId": "key-123"}]}
    ]
    ebs_client_wrapper._kms_client.get_paginator.return_value = mock_paginator

    alias = ebs_client_wrapper.get_kms_alias("key-123")
    assert alias == "alias/test-key"


def test_get_kms_alias_empty(ebs_client_wrapper):
    assert ebs_client_wrapper.get_kms_alias(None) is None


def test_check_optimizer_enrollment_active(ebs_client_wrapper, mocker):
    mock_opt = mocker.Mock()
    mock_opt.get_enrollment_status.return_value = {"status": "Active"}

    ebs_client_wrapper.session.client.return_value = mock_opt

    status = ebs_client_wrapper.check_optimizer_enrollment()
    assert status == "Active"


def test_get_volume_recommendations(ebs_client_wrapper, mocker):
    ebs_client_wrapper._optimizer_enrolled = "Active"

    mock_opt = mocker.Mock()
    mock_opt.get_ebs_volume_recommendations.return_value = {
        "volumeRecommendations": [{"volumeArn": "arn:vol-1", "finding": "NotOptimized"}]
    }
    ebs_client_wrapper.session.client.return_value = mock_opt

    results = ebs_client_wrapper.get_volume_recommendations(["arn:vol-1"])
    assert "arn:vol-1" in results
    assert results["arn:vol-1"]["finding"] == "NotOptimized"


def test_get_volume_metrics_no_data(ebs_client_wrapper, mocker):
    ebs_client_wrapper._cw_client.get_metric_statistics.return_value = {
        "Datapoints": []
    }

    metrics = ebs_client_wrapper.get_volume_metrics("vol-1", days=30)
    assert metrics["VolumeReadOps"] == 0.0
    assert metrics["VolumeWriteOps"] == 0.0
    assert metrics["VolumeIdleTime"] == 0.0
