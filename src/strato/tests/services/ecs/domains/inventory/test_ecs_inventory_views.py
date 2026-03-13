import pytest

from strato.services.ecs.domains.inventory.checks import ECSInventoryResult
from strato.services.ecs.domains.inventory.views import ECSInventoryView


@pytest.fixture
def inventory_result():
    return ECSInventoryResult(
        cluster_name="prod-api-cluster",
        service_name="payment-service",
        account_id="123456789012",
        region="us-east-1",
        vpc_id="vpc-0a1b2c3d",
        tags={"Env": "Prod", "Team": "Payments"},
        task_definition="payment-task-def:5",
        launch_type="FARGATE",
        capacity_provider=None,
        cpu_allocated_vcpu="1024",
        memory_allocated_gb="2048",
        cpu_utilization_avg_30d=45.5,
        memory_utilization_avg_30d=60.0,
        desired_tasks=4,
        running_tasks=4,
        rightsizing_recommendation="Optimized",
        autoscaling_enabled=True,
        scaling_events_30d=12,
        load_balancer_name="payments-alb-tg",
        logging_enabled=True,
        health_check_grace_period_seconds=60,
    )


def test_get_headers():
    headers = ECSInventoryView.get_headers()
    assert "cluster_name" in headers
    assert "cpu_utilization_avg_30d" in headers
    assert "rightsizing_recommendation" in headers
    assert "autoscaling_enabled" in headers


def test_format_csv_row(inventory_result):
    row = ECSInventoryView.format_csv_row(inventory_result)

    # Based on the header order in views.py
    # cluster_name (0)
    # service_name (1)
    # account_id (2)
    # region (3)
    # vpc_id (4)
    # tags (5)

    assert row[0] == "prod-api-cluster"
    assert row[1] == "payment-service"
    assert row[2] == "123456789012"
    assert row[3] == "us-east-1"
    assert "Env=Prod; Team=Payments" in row[5]
    assert row[6] == "payment-task-def:5"
    assert row[7] == "FARGATE"
    assert row[10] == "1024"  # cpu_allocated_vcpu
    assert row[12] == "45.5"  # cpu_utilization_avg_30d
    assert row[21] == "Optimized"  # rightsizing_recommendation
    assert row[24] == "True"  # autoscaling_enabled
    assert row[25] == "12"  # scaling_events_30d
    assert row[26] == "payments-alb-tg"
    assert row[32] == "True"  # logging_enabled
    assert row[33] == "60"  # health_check_grace_period_seconds
