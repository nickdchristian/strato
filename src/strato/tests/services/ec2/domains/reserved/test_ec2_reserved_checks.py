from datetime import UTC, datetime, timedelta

from strato.core.models import InventoryRecord
from strato.services.ec2.domains.reserved.checks import EC2ReservedInstanceScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ec2.domains.reserved.checks.EC2Client"
    )
    mock_client = mock_client_cls.return_value

    mock_session = mocker.Mock(region_name="us-east-1")
    mock_client.session = mock_session

    scanner = EC2ReservedInstanceScanner(account_id="123", session=mock_session)

    start_time = datetime.now(UTC) - timedelta(days=100)
    end_time = datetime.now(UTC) + timedelta(days=265)

    ri_data = {
        "ReservedInstancesId": "ri-123",
        "InstanceType": "m5.large",
        "Scope": "Region",
        "InstanceCount": 5,
        "Start": start_time,
        "End": end_time,
        "Duration": 31536000,
        "OfferingType": "No Upfront",
        "FixedPrice": 0.0,
        "UsagePrice": 0.12,
        "RecurringCharges": [{"Amount": 0.12, "Frequency": "Hourly"}],
        "Tags": [{"Key": "Name", "Value": "Prod-RI"}],
        "State": "active",
    }

    result = scanner.analyze_resource(ri_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "ri-123"
    assert result.region == "us-east-1"

    d = result.details
    assert d["InstanceType"] == "m5.large"
    assert d["TermSeconds"] == 31536000


def test_scanner_analyze_resource_empty_fields(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ec2.domains.reserved.checks.EC2Client"
    )

    mock_session = mocker.Mock(region_name="us-east-1")
    mock_client_cls.return_value.session = mock_session

    scanner = EC2ReservedInstanceScanner(account_id="123", session=mock_session)

    ri_data = {
        "ReservedInstancesId": "ri-empty",
        "Start": datetime.now(UTC),
    }

    result = scanner.analyze_resource(ri_data)

    assert result.resource_name == "ri-empty"
    assert result.details["Tags"] == {}
    assert result.details["RemainingDays"] == 0
