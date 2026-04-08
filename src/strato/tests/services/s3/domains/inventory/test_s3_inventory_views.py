import json

import pytest

from strato.core.models import InventoryRecord
from strato.services.s3.domains.inventory.views import S3InventoryView


@pytest.fixture
def inventory_result():
    return InventoryRecord(
        resource_arn="arn:aws:s3:::full-bucket",
        resource_name="full-bucket",
        region="us-west-2",
        account_id="999",
        details={
            "CreationDate": "2025-05-20T00:00:00",
            "EncryptionType": "aws:kms",
            "KmsMasterKeyId": "alias/key",
            "BucketKeyEnabled": True,
            "VersioningStatus": "Enabled",
            "MfaDelete": "Disabled",
            "BlockAllPublicAccess": True,
            "HasBucketPolicy": True,
            "BucketOwnership": "BucketOwnerEnforced",
            "ServerAccessLogging": "logs-bucket",
            "StaticWebsiteHosting": "Disabled",
            "TransferAcceleration": "Enabled",
            "IntelligentTieringConfig": "Enabled",
            "ObjectLock": "Enabled",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetention": "1 Year",
            "ReplicationStatus": "Enabled",
            "ReplicationDestination": "backup-bucket",
            "ReplicationCostImpact": "Cross-Region",
            "LifecycleStatus": "Enabled",
            "LifecycleRuleCount": 5,
            "TotalBucketSizeGb": 500.55,
            "TotalObjectCount": 10000,
            "AllRequestsCount": 50000,
            "GetRequestsCount": 40000,
            "PutRequestsCount": 10000,
            "StandardSizeGb": 500.55,
            "StandardIaSizeGb": 0.0,
            "IntelligentTieringSizeGb": 0.0,
            "GlacierSizeGb": 0.0,
            "DeepArchiveSizeGb": 0.0,
            "RrsSizeGb": 0.0,
            "GlacierObjectCount": 0,
            "DeepArchiveObjectCount": 0,
            "Tags": {"Project": "Alpha", "Stage": "Prod"},
        },
    )


def test_get_headers():
    headers = S3InventoryView.get_headers("INVENTORY")
    # Test Terminal Headers
    assert "Bucket Name" in headers
    assert "Versioning" in headers
    assert "Encryption" in headers
    assert "Total Size (GB)" in headers
    assert len(headers) == 7


def test_format_row(inventory_result):
    row = S3InventoryView.format_row(inventory_result)

    # Testing the short terminal output
    assert row[0] == "999"  # Account ID
    assert row[1] == "us-west-2"  # Region
    assert row[2] == "full-bucket"
    assert row[3] == "Enabled"  # Versioning
    assert row[4] == "aws:kms"  # Encryption
    assert row[5] == "Yes"  # Public Access Blocked
    assert row[6] == "500.55"  # Total Size


def test_format_csv_row(inventory_result):
    row = S3InventoryView.format_csv_row(inventory_result)

    assert row[0] == "999"  # Account ID
    assert row[2] == "full-bucket"
    assert row[3] == "arn:aws:s3:::full-bucket"
    assert row[4] == "2025-05-20T00:00:00"
    assert row[5] == "aws:kms"
    assert row[7] == "True"  # Bucket Key
    assert row[10] == "True"  # Public Access
    assert row[25] == "500.55"  # Size
    assert row[26] == "10000"  # Count

    tags_col = row[-1]
    assert json.loads(tags_col) == {"Project": "Alpha", "Stage": "Prod"}
