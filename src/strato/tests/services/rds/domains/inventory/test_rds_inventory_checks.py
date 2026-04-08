from strato.core.models import InventoryRecord
from strato.services.rds.domains.inventory.checks import RDSInventoryScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.rds.domains.inventory.checks.RDSClient"
    )
    mock_client = mock_client_cls.return_value

    # Mock metric returns (peak, mean)
    mock_client.get_cpu_utilization.return_value = (80.0, 40.0)
    mock_client.get_database_connections.return_value = (100.0, 10.0)
    mock_client.get_read_throughput.return_value = (500.0, 250.0)
    mock_client.get_write_throughput.return_value = (200.0, 100.0)

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = RDSInventoryScanner(account_id="123", session=mock_session)

    resource_data = {
        "DBInstanceIdentifier": "db-prod",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-prod",
        "Engine": "postgres",
        "EngineVersion": "14.1",
        "AvailabilityZone": "us-east-1a",
        "DBInstanceClass": "db.t3.medium",
        "PubliclyAccessible": True,
        "MultiAZ": False,
        "StorageType": "gp3",
        "AllocatedStorage": 100,
        "StorageEncrypted": True,
        "Endpoint": {"Port": 5432},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
        "OptionGroupMemberships": [{"OptionGroupName": "default:postgres-14"}],
        "EnabledCloudwatchLogsExports": ["postgresql"],
        "TagList": [{"Key": "Env", "Value": "Prod"}],
    }

    result = scanner.analyze_resource(resource_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "db-prod"
    assert result.resource_arn == "arn:aws:rds:us-east-1:123:db:db-prod"
    assert result.region == "us-east-1"

    d = result.details
    assert d["Engine"] == "postgres"
    assert d["Port"] == 5432
    assert d["PubliclyAccessible"] is True
    assert d["SecurityGroupIds"] == ["sg-1"]

    assert d["PeakCpu90d"] == 80.0
    assert d["MeanCpu90d"] == 40.0
    assert d["PeakConnections90d"] == 100.0
    assert d["MeanConnections90d"] == 10.0

    assert d["Tags"] == {"Env": "Prod"}
