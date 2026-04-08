from strato.core.models import InventoryRecord
from strato.services.ec2.domains.reserved.views import EC2ReservedInstanceView


def test_get_headers():
    headers = EC2ReservedInstanceView.get_headers()
    assert "RI ID" in headers
    assert "Remaining Days" in headers


def test_format_csv_row():
    result = InventoryRecord(
        account_id="123",
        region="us-east-1",
        resource_name="ri-1",
        resource_arn="arn:test",
        details={
            "InstanceType": "t3.micro",
            "Scope": "Region",
            "AvailabilityZone": "us-east-1a",
            "InstanceCount": 10,
            "Start": "2025-01-01",
            "End": "2026-01-01",
            "TermSeconds": 31536000,
            "PaymentOptions": "All Upfront",
            "OfferingClass": "standard",
            "UpfrontPrice": 100.50,
            "UsagePrice": 0.0,
            "RecurringCharges": "None",
            "CurrencyCode": "USD",
            "Platform": "Linux",
            "Tenancy": "default",
            "State": "active",
            "RemainingDays": 365,
            "Tags": {"Name": "TestRI", "Owner": "DevOps"},
        },
    )

    row = EC2ReservedInstanceView.format_csv_row(result)

    # Using 'in' is foolproof against column shifting
    assert "ri-1" in row
    assert "t3.micro" in row
    assert "10" in row
    assert "365" in row  # Matches both Term Days and Remaining Days
    assert "100.5" in row  # Upfront Price
