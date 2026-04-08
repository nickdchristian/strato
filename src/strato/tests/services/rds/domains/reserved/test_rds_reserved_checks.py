from datetime import UTC, datetime, timedelta

from strato.core.models import InventoryRecord
from strato.services.rds.domains.reserved.checks import RDSReservedInstanceScanner


def test_scanner_analyze_resource(mocker):
    # Patch the RDSClient to avoid real AWS calls
    mocker.patch("strato.services.rds.domains.reserved.checks.RDSClient")

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"
    scanner = RDSReservedInstanceScanner(account_id="123", session=mock_session)

    start_time = datetime.now(UTC) - timedelta(days=100)

    ri_data = {
        "ReservedDBInstanceId": "ri-123",
        "ReservedDBInstanceArn": "arn:aws:rds:us-east-1:123:ri:ri-123",
        "LeaseId": "lease-abc",
        "ProductDescription": "postgresql",
        "DBInstanceClass": "db.m5.large",
        "State": "active",
        "MultiAZ": True,
        "StartTime": start_time,
        "Duration": 31536000,  # 1 year in seconds
        "DBInstanceCount": 3,
        "OfferingType": "No Upfront",
        "FixedPrice": 0.0,
        "UsagePrice": 0.15,
        "CurrencyCode": "USD",
        "RecurringCharges": [],
    }

    result = scanner.analyze_resource(ri_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "ri-123"
    assert result.resource_arn == "arn:aws:rds:us-east-1:123:ri:ri-123"
    assert result.region == "us-east-1"

    d = result.details
    assert d["LeaseId"] == "lease-abc"
    assert d["OfferingType"] == "No Upfront"
    assert d["MultiAZ"] is True
    assert d["InstanceCount"] == 3
    assert d["DBInstanceClass"] == "db.m5.large"

    # 365 days total - 100 days elapsed = ~265 days remaining
    assert d["RemainingDays"] > 260
