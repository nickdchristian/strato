import uuid
from datetime import datetime

from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanner,
    S3SecurityScanType,
)


def test_security_result_is_pure_data():
    """Ensures the dataclass acts strictly as an inventory container."""
    result = S3SecurityResult(
        resource_arn="arn:aws:s3:::safe-bucket",
        resource_name="safe-bucket",
        region="us-east-1",
        account_id="123",
        public_access_block_status=True,
        check_type=S3SecurityScanType.ALL,
    )

    assert result.status_score == 0
    assert result.status == "PASS"
    assert not result.findings


def test_entropy_calculation():
    """Validates the static method for entropy calculation."""
    assert S3SecurityScanner._calculate_entropy("test") == "HIGH"
    assert S3SecurityScanner._calculate_entropy("backup") == "HIGH"
    assert S3SecurityScanner._calculate_entropy("my-company-backup-2024") == "MODERATE"

    random_bucket = "bucket-" + str(uuid.uuid4())
    assert S3SecurityScanner._calculate_entropy(random_bucket) == "LOW"


def test_scanner_analyze_resource(mocker):
    """Ensures Boto3 responses map properly to the dataclass."""
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.security.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_bucket_region.return_value = "us-west-2"
    mock_client.get_public_access_status.return_value = True
    mock_client.get_bucket_policy.return_value = {
        "Access": "Private",
        "SSL_Enforced": True,
        "Log_Sources": [],
    }
    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "aws:kms",
        "SSECBlocked": True,
    }
    mock_client.get_acl_status.return_value = {"Status": "Disabled"}
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": True,
    }
    mock_client.get_object_lock_details.return_value = {"Status": False}
    mock_client.get_website_hosting_status.return_value = False

    scanner = S3SecurityScanner(check_type=S3SecurityScanType.ALL)

    safe_name = "bucket-" + str(uuid.uuid4())
    bucket_data = {"Name": safe_name, "CreationDate": datetime(2025, 1, 1)}

    result = scanner.analyze_resource(bucket_data)

    assert isinstance(result, S3SecurityResult)
    assert result.resource_name == safe_name
    assert result.region == "us-west-2"
    assert result.public_access_block_status is True
    assert result.ssl_enforced is True
    assert result.encryption == "aws:kms"

    # Crucial check: Assert the scanner left the score at 0
    assert result.status_score == 0
    assert result.status == "PASS"


def test_scanner_partial_scan(mocker):
    """Ensures partial scans don't make unnecessary API calls."""
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.security.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value
    mock_client.get_bucket_region.return_value = "us-east-1"
    mock_client.get_encryption_status.return_value = {"SSEAlgorithm": "AES256"}

    scanner = S3SecurityScanner(check_type=S3SecurityScanType.ENCRYPTION)

    result = scanner.analyze_resource({"Name": "test"})

    assert result.encryption == "AES256"
    mock_client.get_bucket_policy.assert_not_called()
    mock_client.get_versioning_status.assert_not_called()
