from datetime import datetime

from strato.core.models import ObservationLevel
from strato.services.s3.domains.security.checks import (
    S3SecurityResult,
    S3SecurityScanner,
    S3SecurityScanType,
)


def test_security_result_is_pure_data():
    """Ensures the dataclass defaults to 0 score and empty findings."""
    result = S3SecurityResult(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_name="test-bucket",
        region="us-east-1",
        account_id="123456789012",
    )

    assert result.status_score == ObservationLevel.PASS
    assert len(result.findings) == 0
    assert result.status == "PASS"


def test_scanner_extracts_pure_facts(mocker):
    """Ensures the scanner parses Boto3 data into the dataclass correctly."""
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.security.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value

    # Mock the pure facts
    mock_client.get_bucket_region.return_value = "us-east-1"
    mock_client.get_public_access_status.return_value = True
    mock_client.get_bucket_policy.return_value = {
        "Access": "Private",
        "SSL_Enforced": True,
        "Log_Sources": [],
    }
    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "AES256",
        "SSECBlocked": True,
    }
    mock_client.get_acl_status.return_value = {"Status": "Disabled"}
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": False,
    }
    mock_client.get_object_lock_details.return_value = {"Status": False}
    mock_client.get_website_hosting_status.return_value = False

    scanner = S3SecurityScanner(check_type=S3SecurityScanType.ALL)

    bucket_data = {"Name": "test-security-bucket", "CreationDate": datetime(2024, 1, 1)}
    result = scanner.analyze_resource(bucket_data)

    # Assert that the facts were mapped properly
    assert isinstance(result, S3SecurityResult)
    assert result.resource_name == "test-security-bucket"
    assert result.public_access_block_status is True
    assert result.ssl_enforced is True
    assert result.versioning == "Enabled"

    # Assert no opinions were formed during data gathering
    assert result.status_score == 0
    assert len(result.findings) == 0
