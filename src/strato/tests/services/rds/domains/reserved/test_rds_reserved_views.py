import json

from strato.core.models import InventoryRecord
from strato.services.rds.domains.reserved.views import RDSReservedInstanceView


def test_get_headers():
    headers = RDSReservedInstanceView.get_headers()
    # Test Terminal Headers
    assert "RI ID" in headers
    assert "Class" in headers
    assert "Product" in headers
    assert "Remaining Days" in headers
    assert len(headers) == 7


def test_format_csv_row():
    result = InventoryRecord(
        account_id="123",
        region="us-east-1",
        resource_name="ri-1",
        resource_arn="arn:test",
        details={
            "LeaseId": "lease-1",
            "ProductDescription": "postgresql",
            "DBInstanceClass": "db.t3.micro",
            "OfferingType": "No Upfront",
            "State": "active",
            "MultiAZ": True,
            "StartTime": "2025-01-01T00:00:00",
            "DurationSeconds": 31536000,
            "RemainingDays": 300,
            "InstanceCount": 5,
            "FixedPrice": 0.0,
            "UsagePrice": 0.10,
            "CurrencyCode": "USD",
            "RecurringCharges": [{"Amount": 0.10, "Frequency": "Hourly"}],
        },
    )

    row = RDSReservedInstanceView.format_csv_row(result)

    assert row[0] == "123"
    assert row[1] == "us-east-1"
    assert row[2] == "ri-1"  # RI ID
    assert row[3] == "arn:test"
    assert row[4] == "lease-1"
    assert row[5] == "postgresql"
    assert row[6] == "db.t3.micro"
    assert row[7] == "No Upfront"
    assert row[8] == "active"
    assert row[9] == "True"  # Multi-AZ
    assert row[11] == "365"  # Term (Days)
    assert row[12] == "300"  # Remaining Days
    assert row[13] == "5"  # Instance Count

    # Verify recurring charges JSON
    assert json.loads(row[17]) == [{"Amount": 0.10, "Frequency": "Hourly"}]
