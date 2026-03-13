from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from strato.services.ecs.client import ECSClient, safe_aws_call


@pytest.fixture
def mock_boto_session():
    with patch("boto3.Session") as mock_session:
        yield mock_session.return_value


@pytest.fixture
def ecs_client(mock_boto_session):
    return ECSClient(session=mock_boto_session)


def test_safe_aws_call_decorator_success():
    @safe_aws_call(default="failed")
    def successful_call():
        return "success"

    assert successful_call() == "success"


def test_safe_aws_call_decorator_client_error():
    @safe_aws_call(default=[])
    def failing_call():
        error_response = {"Error": {"Code": "AccessDeniedException"}}
        raise ClientError(error_response, "operation_name")

    assert failing_call() == []


def test_safe_aws_call_decorator_generic_error():
    @safe_aws_call(default={})
    def crashing_call():
        raise ValueError("Something unexpected happened")

    assert crashing_call() == {}


def test_list_clusters(ecs_client):
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"clusterArns": ["arn:aws:ecs:us-east-1:123:cluster/c1"]},
        {"clusterArns": ["arn:aws:ecs:us-east-1:123:cluster/c2"]},
    ]
    ecs_client._client.get_paginator.return_value = mock_paginator

    clusters = ecs_client.list_clusters()

    assert len(clusters) == 2
    assert "arn:aws:ecs:us-east-1:123:cluster/c1" in clusters
    ecs_client._client.get_paginator.assert_called_with("list_clusters")


def test_list_services(ecs_client):
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"serviceArns": ["arn:aws:ecs:us-east-1:123:service/c1/s1"]},
    ]
    ecs_client._client.get_paginator.return_value = mock_paginator

    services = ecs_client.list_services("arn:aws:ecs:us-east-1:123:cluster/c1")

    assert len(services) == 1
    assert "arn:aws:ecs:us-east-1:123:service/c1/s1" in services
    mock_paginator.paginate.assert_called_with(
        cluster="arn:aws:ecs:us-east-1:123:cluster/c1"
    )


def test_describe_services_chunking(ecs_client):
    # Create 15 dummy services to test the 10-item chunking logic
    dummy_arns = [f"svc-{i}" for i in range(15)]

    # Mock return values for two chunks
    ecs_client._client.describe_services.side_effect = [
        {"services": [{"serviceName": f"svc-{i}"} for i in range(10)]},
        {"services": [{"serviceName": f"svc-{i}"} for i in range(10, 15)]},
    ]

    result = ecs_client.describe_services("test-cluster", dummy_arns)

    assert len(result) == 15
    assert ecs_client._client.describe_services.call_count == 2

    # Check first chunk call
    args, kwargs = ecs_client._client.describe_services.call_args_list[0]
    assert kwargs["cluster"] == "test-cluster"
    assert len(kwargs["services"]) == 10

    # Check second chunk call
    args, kwargs = ecs_client._client.describe_services.call_args_list[1]
    assert len(kwargs["services"]) == 5


def test_describe_services_empty(ecs_client):
    result = ecs_client.describe_services("test-cluster", [])
    assert result == []
    ecs_client._client.describe_services.assert_not_called()


def test_describe_task_definition(ecs_client):
    ecs_client._client.describe_task_definition.return_value = {
        "taskDefinition": {"cpu": "256", "memory": "512"}
    }

    result = ecs_client.describe_task_definition("arn:task-def")

    assert result == {"cpu": "256", "memory": "512"}
    ecs_client._client.describe_task_definition.assert_called_with(
        taskDefinition="arn:task-def"
    )


def test_get_service_metric(ecs_client):
    ecs_client._cw_client.get_metric_statistics.return_value = {
        "Datapoints": [
            {"Average": 10.5, "Maximum": 45.0},
            {"Average": 12.0, "Maximum": 50.0},
        ]
    }

    result = ecs_client.get_service_metric("cluster-a", "service-b", "CPUUtilization")

    assert result["avg"] == 11.25  # (10.5 + 12.0) / 2
    assert result["max"] == 50.0


def test_get_service_metric_empty(ecs_client):
    ecs_client._cw_client.get_metric_statistics.return_value = {"Datapoints": []}

    result = ecs_client.get_service_metric("cluster-a", "service-b", "CPUUtilization")

    assert result == {"avg": 0.0, "max": 0.0}


def test_is_autoscaling_enabled(ecs_client):
    ecs_client._app_autoscaling_client.describe_scalable_targets.return_value = {
        "ScalableTargets": [{"ResourceId": "service/cluster/svc"}]
    }

    assert ecs_client.is_autoscaling_enabled("cluster", "svc") is True


def test_is_autoscaling_disabled(ecs_client):
    ecs_client._app_autoscaling_client.describe_scalable_targets.return_value = {
        "ScalableTargets": []
    }

    assert ecs_client.is_autoscaling_enabled("cluster", "svc") is False


def test_get_scaling_events_count(ecs_client):
    mock_paginator = MagicMock()

    now = datetime.now(UTC)
    recent_event = now - timedelta(days=2)
    old_event = now - timedelta(days=40)

    # Mock page 1 with one recent event,
    # page 2 with one old event (should stop counting)
    mock_paginator.paginate.return_value = [
        {"ScalingActivities": [{"StartTime": recent_event}]},
        {"ScalingActivities": [{"StartTime": old_event}]},
    ]
    ecs_client._app_autoscaling_client.get_paginator.return_value = mock_paginator

    count = ecs_client.get_scaling_events_count("cluster", "svc", days=30)

    assert count == 1
    ecs_client._app_autoscaling_client.get_paginator.assert_called_with(
        "describe_scaling_activities"
    )
