from unittest import mock

from typer.testing import CliRunner

from strato.services.ec2.cli.inventory import app
from strato.services.ec2.domains.inventory.checks import EC2InventoryScanType

runner = CliRunner(mix_stderr=False)


def invoke_scan(args, mock_context_obj=None):
    cmd = app.registered_commands[0].name if app.registered_commands else "scan"

    mock_context_obj = mock_context_obj or {
        "session": mock.Mock(),
        "account_id": "123456789012",
    }

    res = runner.invoke(app, [cmd] + args, obj=mock_context_obj)
    if res.exit_code == 2:
        return runner.invoke(app, args, obj=mock_context_obj)
    return res


@mock.patch("strato.services.ec2.cli.inventory.run_scan")
def test_inventory_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--json", "--region", "us-west-2"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    # Updated to expect ALL
    assert kwargs["check_type"] == EC2InventoryScanType.ALL


@mock.patch("strato.services.ec2.cli.inventory.run_scan")
def test_inventory_scan_custom_role(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--csv", "--org-role", "AuditRole", "--region", "us-east-1"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["org_role"] == "AuditRole"
