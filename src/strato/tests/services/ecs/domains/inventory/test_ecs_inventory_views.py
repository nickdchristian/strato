import json

import pytest

from strato.core.models import InventoryRecord
from strato.services.ecs.domains.inventory.views import ECSInventoryView


@pytest.fixture
def inventory_result():
    return InventoryRecord(
        resource_arn="arn:aws:ecs:us-east-1:123456789012:service/prod-api-cluster/payment-service",
        resource_name="payment-service",
        region="us-east-1",
        account_id="123456789012",
        details={
            "ClusterName": "prod-api-cluster",
            "TaskDefinition": "payment-task-def:5",
            "LaunchType": "FARGATE",
            "CapacityProvider": None,
            "CpuAllocatedVcpu": "1024",
            "MemoryAllocatedGb": "2048",
            "CpuUtilizationAvg30d": 45.5,
            "CpuUtilizationPeak30d": 65.0,
            "MemoryUtilizationAvg30d": 60.0,
            "MemoryUtilizationPeak30d": 75.0,
            "DesiredTasks": 4,
            "RunningTasks": 4,
            "LastDeploymentDaysAgo": 2,
            "RightsizingRecommendation": "Optimized",
            "LoadBalancerNames": ["payments-alb-tg"],
            "HealthCheckGracePeriodSeconds": 60,
            "LoggingEnabled": True,
            "AutoscalingEnabled": True,
            "ScalingEvents30d": 12,
            "Tags": {"Env": "Prod", "Team": "Payments"},
        },
    )


def test_get_headers():
    headers = ECSInventoryView.get_headers()
    # Testing terminal headers
    assert "Cluster Name" in headers
    assert "Launch Type" in headers
    assert "Tasks (Run/Des)" in headers
    assert "Rec" in headers


def test_format_csv_row(inventory_result):
    row = ECSInventoryView.format_csv_row(inventory_result)

    assert row[0] == "123456789012"  # Account ID
    assert row[1] == "us-east-1"  # Region
    assert row[2] == "prod-api-cluster"
    assert row[3] == "payment-service"
    assert (
        row[4]
        == "arn:aws:ecs:us-east-1:123456789012:service/prod-api-cluster/payment-service"
    )
    assert row[5] == "payment-task-def:5"
    assert row[6] == "FARGATE"
    assert row[7] == ""  # CapacityProvider is None
    assert row[8] == "1024"  # CpuAllocatedVcpu
    assert row[10] == "45.5"  # CpuUtilizationAvg30d
    assert row[14] == "4"  # DesiredTasks
    assert row[16] == "2"  # LastDeploymentDaysAgo
    assert row[17] == "Optimized"  # RightsizingRecommendation
    assert row[18] == "payments-alb-tg"
    assert row[20] == "True"  # LoggingEnabled
    assert row[21] == "True"  # AutoscalingEnabled
    assert row[22] == "12"  # ScalingEvents30d

    assert json.loads(row[-1]) == {"Env": "Prod", "Team": "Payments"}
