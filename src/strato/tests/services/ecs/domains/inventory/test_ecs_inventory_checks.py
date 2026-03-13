from datetime import UTC, datetime, timedelta

from strato.services.ecs.domains.inventory.checks import (
    ECSInventoryResult,
    ECSInventoryScanner,
)


def test_result_serialization():
    result = ECSInventoryResult(
        resource_arn="arn:aws:ecs:us-east-1:123:service/cluster/svc",
        resource_id="svc",
        service_name="test-svc",
        cluster_name="test-cluster",
        cpu_utilization_avg_30d=15.5,
        tags={"Env": "Test"},
    )

    data = result.to_dict()

    assert "findings" not in data
    assert "status_score" not in data
    assert data["service_name"] == "test-svc"
    assert data["cpu_utilization_avg_30d"] == 15.5
    assert data["tags"] == {"Env": "Test"}


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

    scanner = ECSInventoryScanner(account_id="123")

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

    assert isinstance(result, ECSInventoryResult)
    assert result.cluster_name == "prod-cluster"
    assert result.service_name == "web-svc"
    assert result.resource_id == "web-svc"
    assert result.region == "us-west-2"
    assert result.tags == {"Project": "Apollo"}

    assert result.task_definition == "web-task:10"
    assert result.cpu_allocated_vcpu == "512"
    assert result.memory_allocated_gb == "1024"
    assert result.logging_enabled is True

    assert result.load_balancer_name == "web-tg"
    assert result.health_check_grace_period_seconds == 120
    assert result.last_deployment_days_ago == 2

    assert result.cpu_utilization_avg_30d == 10.0
    assert result.memory_utilization_peak_30d == 28.0

    # Check recommendation logic triggered by < 30 max thresholds
    assert result.rightsizing_recommendation == "Underutilized (Scale In / Downsize)"

    assert result.autoscaling_enabled is True
    assert result.scaling_events_30d == 3


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

    scanner = ECSInventoryScanner(account_id="999")

    resource_data = {
        "_ClusterArn": "arn:aws:ecs:us-east-1:999:cluster/batch-cluster",
        "serviceName": "data-worker",
    }

    result = scanner.analyze_resource(resource_data)

    assert result.rightsizing_recommendation == "Overutilized (Scale Out / Upsize)"
    assert result.autoscaling_enabled is False
    assert result.scaling_events_30d == 0
