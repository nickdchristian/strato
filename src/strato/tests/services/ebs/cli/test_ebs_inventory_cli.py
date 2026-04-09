from unittest import mock

from typer.testing import CliRunner

from strato.services.ebs.cli.inventory import app
from strato.services.ebs.domains.inventory.checks import (
    EBSInventoryScanner,
    EBSInventoryScanType,
)
from strato.services.ebs.domains.inventory.views import EBSInventoryView

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


@mock.patch("strato.services.ebs.cli.inventory.run_scan")
def test_scan_with_json_and_region(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--json", "--region", "us-west-2"])

    assert result.exit_code == 0
    mock_run_scan.assert_called_once_with(
        scanner_cls=EBSInventoryScanner,
        check_type=EBSInventoryScanType.VOLUMES,
        verbose=False,
        json_output=True,
        csv_output=False,
        org_role=None,
        view_class=EBSInventoryView,
        region="us-west-2",
        session=mock.ANY,
        account_id="123456789012",
    )


@mock.patch("strato.services.ebs.cli.inventory.run_scan")
def test_scan_with_csv_verbose_and_role(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(
        ["--csv", "--verbose", "--org-role", "arn:aws:iam::123:role/audit"]
    )

    assert result.exit_code == 0
    mock_run_scan.assert_called_once_with(
        scanner_cls=EBSInventoryScanner,
        check_type=EBSInventoryScanType.VOLUMES,
        verbose=True,
        json_output=False,
        csv_output=True,
        org_role="arn:aws:iam::123:role/audit",
        view_class=EBSInventoryView,
        region=None,
        session=mock.ANY,
        account_id="123456789012",
    )
