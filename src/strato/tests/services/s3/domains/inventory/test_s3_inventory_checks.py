from datetime import datetime

from strato.core.models import InventoryRecord
from strato.services.s3.domains.inventory.checks import S3InventoryScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.s3.domains.inventory.checks.S3Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_bucket_region.return_value = "us-east-1"
    mock_client.get_bucket_tags.return_value = {"Env": "Prod"}
    mock_client.get_encryption_status.return_value = {
        "SSEAlgorithm": "AES256",
        "KMSMasterKeyID": None,
        "BucketKeyEnabled": False,
    }
    mock_client.get_versioning_status.return_value = {
        "Status": "Enabled",
        "MFADelete": False,
    }
    mock_client.get_bucket_policy.return_value = {
        "Access": "Private",
        "SSL_Enforced": True,
    }
    mock_client.get_public_access_status.return_value = True
    mock_client.get_object_lock_details.return_value = {"Status": False}
    mock_client.get_replication_configuration.return_value = []
    mock_client.get_lifecycle_configuration.return_value = []
    mock_client.get_intelligent_tiering_configurations.return_value = []
    mock_client.get_acl_status.return_value = {
        "Status": "Disabled",
        "Ownership": "BucketOwnerEnforced",
    }
    mock_client.get_logging_status.return_value = "logs-bucket"
    mock_client.get_website_hosting_status.return_value = False
    mock_client.get_accelerate_configuration.return_value = "Suspended"
    mock_client.get_request_payment.return_value = "BucketOwner"
    mock_client.get_cors_count.return_value = 0
    mock_client.get_notification_configuration_count.return_value = 0
    mock_client.get_inventory_configuration_count.return_value = 0
    mock_client.get_analytics_configuration_count.return_value = 0
    mock_client.get_metrics_configuration_count.return_value = 0

    mock_client.get_bucket_metrics.return_value = {
        "Storage": {
            "Standard": {"Size": 10.5, "Count": 100},
            "Standard-IA": {"Size": 0.0, "Count": 0},
            "Intelligent-Tiering": {"Size": 0.0, "Count": 0},
            "RRS": {"Size": 0.0, "Count": 0},
            "Glacier": {"Size": 0.0, "Count": 0},
            "Glacier-Deep-Archive": {"Size": 0.0, "Count": 0},
        },
        "Requests": {"All": 50, "Get": 40, "Put": 10},
    }
    mock_client.calculate_replication_cost_impact.return_value = []

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = S3InventoryScanner(account_id="123", session=mock_session)

    bucket_data = {"Name": "test-bucket", "CreationDate": datetime(2025, 1, 1)}
    result = scanner.analyze_resource(bucket_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "test-bucket"
    assert result.resource_arn == "arn:aws:s3:::test-bucket"
    assert result.region == "us-east-1"

    d = result.details
    assert d["EncryptionType"] == "AES256"
    assert d["BlockAllPublicAccess"] is True
    assert d["VersioningStatus"] == "Enabled"
    assert d["TotalBucketSizeGb"] == 10.5
    assert d["TotalObjectCount"] == 100
    assert d["Tags"] == {"Env": "Prod"}
