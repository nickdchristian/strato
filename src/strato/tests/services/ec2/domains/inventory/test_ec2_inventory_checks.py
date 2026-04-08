from datetime import datetime

from strato.core.models import InventoryRecord
from strato.services.ec2.domains.inventory.checks import EC2InventoryScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ec2.domains.inventory.checks.EC2Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.check_optimizer_enrollment.return_value = "Active"
    mock_client.get_volume_details.return_value = {
        "vol-1": {"Encrypted": True, "Size": 50},
        "vol-2": {"Encrypted": False, "Size": 50},
    }
    mock_client.get_image_details.return_value = {
        "Name": "MyAMI",
        "OwnerAlias": "amazon",
        "CreationDate": "2024-01-01",
    }
    mock_client.get_cpu_utilization.return_value = 45.0
    mock_client.get_memory_utilization.return_value = None
    mock_client.get_network_utilization.return_value = 100.0
    mock_client.get_security_group_rules.return_value = {
        "Inbound": ["80", "443"],
        "Outbound": ["All"],
    }
    mock_client.is_instance_managed.return_value = True
    mock_client.get_termination_protection.return_value = False

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = EC2InventoryScanner(account_id="123", session=mock_session)
    scanner.optimizer_status = "Active"

    instance_data = {
        "InstanceId": "i-12345",
        "InstanceType": "t3.medium",
        "State": {"Name": "running"},
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "PrivateIpAddress": "10.0.0.1",
        "PublicIpAddress": "1.2.3.4",
        "LaunchTime": datetime(2025, 1, 1),
        "ImageId": "ami-1",
        "VpcId": "vpc-1",
        "BlockDeviceMappings": [
            {"Ebs": {"VolumeId": "vol-1"}},
            {"Ebs": {"VolumeId": "vol-2"}},
        ],
        "SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}],
        "Tags": [{"Key": "Name", "Value": "ProdWeb"}],
    }

    result = scanner.analyze_resource(instance_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "ProdWeb"
    assert result.resource_arn == "arn:aws:ec2:us-east-1:123:instance/i-12345"
    assert result.region == "us-east-1"

    d = result.details
    assert d["ManagedBySSM"] is True
    assert d["AttachedVolumeCount"] == 2
    assert d["AttachedVolumeEncryption"] == "Mixed"
    assert d["HighestCpu14d"] == 45.0
    assert d["HighestMem14d"] is None
    assert d["SecurityGroupCount"] == 2
    assert d["SecurityGroupIds"] == ["sg-1", "sg-2"]
    assert d["SecurityGroupInboundPorts"] == ["80", "443"]


def test_scanner_optimizer_disabled(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.ec2.domains.inventory.checks.EC2Client"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_image_details.return_value = {}
    mock_client.get_volume_details.return_value = {}
    mock_client.get_security_group_rules.return_value = {
        "Inbound": [],
        "Outbound": [],
    }

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = EC2InventoryScanner(account_id="123", session=mock_session)
    scanner.optimizer_status = "Disabled"

    instance_data = {
        "InstanceId": "i-1",
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "Tags": [],
    }

    result = scanner.analyze_resource(instance_data)
    assert result.details["RightsizingRecommendation"] == "OptimizerDisabled"
