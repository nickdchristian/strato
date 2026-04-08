import json

import pytest

from strato.core.models import InventoryRecord
from strato.services.rds.domains.inventory.views import RDSInventoryView


@pytest.fixture
def inventory_result():
    return InventoryRecord(
        resource_arn="arn:aws:rds:us-east-1:999:db:db-prod",
        resource_name="db-prod",
        region="us-east-1",
        account_id="999",
        details={
            "DbClusterIdentifier": "",
            "State": "available",
            "Engine": "postgres",
            "EngineVersion": "14.1",
            "AvailabilityZone": "us-east-1a",
            "InstanceClass": "db.t3.medium",
            "VpcId": "vpc-123",
            "Port": 5432,
            "SecurityGroupIds": ["sg-1", "sg-2"],
            "PubliclyAccessible": False,
            "MultiAz": True,
            "StorageType": "gp3",
            "AllocatedStorageGb": 100,
            "MaxAllocatedStorageGb": 500,
            "StorageEncrypted": True,
            "ProvisionedIops": 3000,
            "StorageThroughput": 125,
            "IamAuthEnabled": False,
            "CaCertificateIdentifier": "rds-ca-2019",
            "ParameterGroups": ["default.postgres14"],
            "OptionGroups": ["default:postgres"],
            "CloudwatchLogExports": ["postgresql"],
            "PeakCpu90d": 80.0,
            "MeanCpu90d": 40.0,
            "PeakConnections90d": 100.0,
            "MeanConnections90d": 10.0,
            "PeakReadThroughput90d": 500.0,
            "MeanReadThroughput90d": 250.0,
            "PeakWriteThroughput90d": 200.0,
            "MeanWriteThroughput90d": 100.0,
            "BackupRetentionPeriodDays": 7,
            "PreferredBackupWindow": "04:00-04:30",
            "PreferredMaintenanceWindow": "sun:05:00-sun:05:30",
            "AutoMinorVersionUpgrade": True,
            "DeletionProtection": True,
            "PerformanceInsightsEnabled": True,
            "MonitoringIntervalSeconds": 60,
            "LicenseModel": "postgresql-license",
            "Tags": {"Env": "Prod"},
        },
    )


def test_get_headers():
    headers = RDSInventoryView.get_headers("INVENTORY")
    # Test Terminal Headers
    assert "DB Identifier" in headers
    assert "Engine" in headers
    assert "Class" in headers
    assert "Storage (GB)" in headers
    assert len(headers) == 8


def test_format_csv_row(inventory_result):
    row = RDSInventoryView.format_csv_row(inventory_result)

    assert row[0] == "999"  # Account ID
    assert row[1] == "us-east-1"  # Region
    assert row[2] == "db-prod"  # Resource Name
    assert row[3] == "arn:aws:rds:us-east-1:999:db:db-prod"
    assert row[6] == "postgres"  # Engine
    assert row[9] == "db.t3.medium"  # Class
    assert row[11] == "5432"  # Port
    assert row[12] == "sg-1;sg-2"  # Security Groups
    assert row[13] == "False"  # PubliclyAccessible
    assert row[16] == "100"  # AllocatedStorageGb
    assert row[23] == "default.postgres14"  # ParameterGroups
    assert row[24] == "default:postgres"  # OptionGroups
    assert row[26] == "80.0"  # PeakCpu90d

    assert json.loads(row[-1]) == {"Env": "Prod"}
