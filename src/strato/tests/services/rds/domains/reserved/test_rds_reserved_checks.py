from datetime import UTC, datetime, timedelta

from strato.services.rds.domains.reserved.checks import (
    RDSReservedInstanceResult,
    RDSReservedInstanceScanner,
)


def test_result_serialization():
    result = RDSReservedInstanceResult(
        reservation_id="ri-1", lease_id="lease-1", remaining_days=300, multi_az=True
    )

    data = result.to_dict()

    assert data["reservation_id"] == "ri-1"
    assert data["multi_az"] is True
    assert data["remaining_days"] == 300
    assert "findings" not in data


def test_scanner_analyze_resource(mocker):
    # Patch the RDSClient to avoid real AWS calls
    mocker.patch("strato.services.rds.domains.reserved.checks.RDSClient")

    scanner = RDSReservedInstanceScanner(account_id="123")

    # Create a mock session and set the region_name property properly
    mock_session = mocker.Mock()
    type(mock_session).region_name = mocker.PropertyMock(return_value="us-east-1")

    # Inject the mock session into the scanner
    scanner.session = mock_session

    # Ensure the client's session (if instantiated) also reflects the region
    if hasattr(scanner.client, "session"):
        scanner.client.session = mock_session

    start_time = datetime.now(UTC) - timedelta(days=100)

    ri_data = {
        "ReservedDBInstanceId": "ri-123",
        "LeaseId": "lease-abc",
        "ProductDescription": "postgresql",
        "DBInstanceClass": "db.m5.large",
        "State": "active",
        "MultiAZ": True,
        "StartTime": start_time,
        "Duration": 31536000,  # 1 year in seconds
        "DBInstanceCount": 3,
        "OfferingType": "No Upfront",
    }

    result = scanner.analyze_resource(ri_data)

    assert isinstance(result, RDSReservedInstanceResult)
    assert result.reservation_id == "ri-123"
    assert result.lease_id == "lease-abc"
    assert result.offering_type == "No Upfront"
    assert result.region == "us-east-1"

    # 365 days total - 100 days elapsed = ~265 days remaining
    assert result.remaining_days > 260
    assert result.multi_az is True
    assert result.quantity == 3
