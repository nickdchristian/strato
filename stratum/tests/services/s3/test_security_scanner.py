from unittest.mock import patch
from datetime import datetime
from stratum.services.s3.audit import S3Scanner, S3Result


@patch("stratum.services.s3.audit.S3Client")
def test_scanner_analyze_resource(mock_client_cls):
    mock_client = mock_client_cls.return_value
    mock_client.get_bucket_region.return_value = "eu-west-1"
    mock_client.get_public_access_status.return_value = False  # Risk
    mock_client.get_encryption_status.return_value = "None"  # Risk

    raw_bucket_data = {
        "Name": "risk-bucket",
        "BucketArn": "arn:aws:s3:::risk-bucket",
        "CreationDate": datetime(2023, 5, 5),
    }

    scanner = S3Scanner()
    result = scanner.analyze_resource(raw_bucket_data)

    assert isinstance(result, S3Result)
    assert result.resource_name == "risk-bucket"
    assert result.region == "eu-west-1"

    assert result.risk_level == "CRITICAL"
    assert len(result.risk_reasons) == 2
