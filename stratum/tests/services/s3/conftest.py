import pytest
from datetime import datetime
from stratum.services.s3.audit import S3Result, S3ScanType


@pytest.fixture
def base_s3_result():
    """Returns a perfectly safe S3 result to modify in tests."""
    return S3Result(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_name="test-bucket",
        region="us-east-1",
        creation_date=datetime(2023, 1, 1),
        public_access_blocked=True,
        encryption="AES256",
        check_type=S3ScanType.ALL,
    )
