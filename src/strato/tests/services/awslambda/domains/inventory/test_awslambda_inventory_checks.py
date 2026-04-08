from strato.core.models import InventoryRecord
from strato.services.awslambda.domains.inventory.checks import LambdaInventoryScanner


def test_scanner_analyze_resource(mocker):
    mock_client_cls = mocker.patch(
        "strato.services.awslambda.domains.inventory.checks.LambdaClient"
    )
    mock_client = mock_client_cls.return_value

    mock_client.get_function_url_details.return_value = ("https://url", "NONE")
    mock_client.get_tags.return_value = {"Owner": "Platform"}
    mock_client.get_function_aliases.return_value = ["prod"]

    mock_session = mocker.Mock()
    mock_session.region_name = "us-east-1"

    scanner = LambdaInventoryScanner(
        check_type="INVENTORY", session=mock_session, account_id="123"
    )

    func_data = {
        "FunctionName": "my-func",
        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:my-func",
        "Runtime": "python3.11",
        "MemorySize": 1024,
        "Timeout": 30,
        "State": "Active",
        "Architectures": ["x86_64"],
        "LastModified": "2025-01-01T00:00:00",
        "Environment": {"Variables": {"LOG_LEVEL": "DEBUG", "DB_HOST": "localhost"}},
    }

    result = scanner.analyze_resource(func_data)

    assert isinstance(result, InventoryRecord)
    assert result.resource_name == "my-func"
    assert result.resource_arn == "arn:aws:lambda:us-east-1:123:function:my-func"

    d = result.details
    assert d["Runtime"] == "python3.11"
    assert d["MemorySize"] == 1024
    assert d["Timeout"] == 30
    assert d["Architecture"] == "x86_64"
    assert "LOG_LEVEL" in d["EnvironmentKeys"]
    assert "DB_HOST" in d["EnvironmentKeys"]
    assert d["Aliases"] == ["prod"]
    assert d["Tags"] == {"Owner": "Platform"}
    assert d["FunctionUrl"] == "https://url"
