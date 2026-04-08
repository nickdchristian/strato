from unittest import mock

from typer.testing import CliRunner

from strato.services.s3.cli.inventory import app
from strato.services.s3.domains.inventory.checks import S3InventoryScanType

runner = CliRunner(mix_stderr=False)


def invoke_scan(args):
    cmd = app.registered_commands[0].name if app.registered_commands else "scan"
    res = runner.invoke(app, [cmd] + args)
    if res.exit_code == 2:
        return runner.invoke(app, args)
    return res


@mock.patch("strato.services.s3.cli.inventory.run_scan")
def test_inventory_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--json"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == S3InventoryScanType.ALL


@mock.patch("strato.services.s3.cli.inventory.run_scan")
def test_inventory_scan_custom_flags(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--csv", "--verbose", "--org-role", "audit-role"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["org_role"] == "audit-role"
