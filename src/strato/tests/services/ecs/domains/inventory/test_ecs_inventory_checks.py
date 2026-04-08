from datetime import UTC, datetime, timedelta

from strato.core.models import InventoryRecord
from strato.services.ecs.domains.inventory.checks import ECSInventoryScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ecs.domains.inventory.checks.ECSClient"
    )
    mock_client = mock_client_cls.return_value

    mock_client.describe_task_definition.return_value = {
        "cpu": "512",
        "memory": "1024",
        "containerDefinitions": [{"logConfiguration": {"logDriver": "awslogs"}}],
    }

    # Return underutilized metrics to trigger scale-in recommendation
    mock_client.get_service_metric.side_effect = [
        {"avg": 10.0, "max": 25.0},  # CPU metrics
        {"avg": 15.0, "max": 28.0},  # Memory metrics
    ]
    mock_client.is_autoscaling_enabled.return_value = True
    mock_client.get_scaling_events_count.return_value = 3

    mock_session = mocker.Mock()
    mock_session.region_name = "us-west-2"

    scanner = ECSInventoryScanner(account_id="123", session=mock_session)

    recent_deploy = datetime.now(UTC) - timedelta(days=2)

    resource_data = {
        "_ClusterArn": "arn:aws:ecs:us-west-2:123:cluster/prod-cluster",
        "serviceArn": "arn:aws:ecs:us-west-2:123:service/prod-cluster/web-svc",
        "serviceName": "web-svc",
        "tags": [{"key": "Project", "value": "Apollo"}],
        "loadBalancers": [{"targetGroupArn": "targetgroup/web-tg/123"}],
        "taskDefinition": "arn:aws:ecs:us-west-2:123:task-definition/web-task:10",
        "launchType": "FARGATE",
        "desiredCount": 2,
        "runningCount": 2,
        "deployments": [{"createdAt": recent_deploy}],
        "healthCheckGracePeriodSeconds": 120,
    }

    result = scanner.analyze_resource(resource_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "web-svc"
    assert (
        result.resource_arn == "arn:aws:ecs:us-west-2:123:service/prod-cluster/web-svc"
    )
    assert result.region == "us-west-2"

    d = result.details
    assert d["ClusterName"] == "prod-cluster"
    assert d["TaskDefinition"] == "web-task:10"
    assert d["CpuAllocatedVcpu"] == "512"
    assert d["MemoryAllocatedGb"] == "1024"
    assert d["LoggingEnabled"] is True

    assert d["LoadBalancerNames"] == ["web-tg"]
    assert d["HealthCheckGracePeriodSeconds"] == 120
    assert d["LastDeploymentDaysAgo"] == 2

    assert d["CpuUtilizationAvg30d"] == 10.0
    assert d["MemoryUtilizationPeak30d"] == 28.0

    assert d["RightsizingRecommendation"] == "Underutilized (Scale In / Downsize)"
    assert d["AutoscalingEnabled"] is True
    assert d["ScalingEvents30d"] == 3
    assert d["Tags"] == {"Project": "Apollo"}


def test_scanner_analyze_resource_overutilized(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ecs.domains.inventory.checks.ECSClient"
    )
    mock_client = mock_client_cls.return_value
    mock_client.describe_task_definition.return_value = {}

    # Return overutilized metrics
    mock_client.get_service_metric.side_effect = [
        {"avg": 80.0, "max": 95.0},  # CPU metrics
        {"avg": 60.0, "max": 75.0},  # Memory metrics
    ]
    mock_client.is_autoscaling_enabled.return_value = False

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = ECSInventoryScanner(account_id="999", session=mock_session)

    resource_data = {
        "_ClusterArn": "arn:aws:ecs:us-east-1:999:cluster/batch-cluster",
        "serviceName": "data-worker",
    }

    result = scanner.analyze_resource(resource_data)

    assert (
        result.details["RightsizingRecommendation"]
        == "Overutilized (Scale Out / Upsize)"
    )
    assert result.details["AutoscalingEnabled"] is False
    assert result.details["ScalingEvents30d"] == 0
