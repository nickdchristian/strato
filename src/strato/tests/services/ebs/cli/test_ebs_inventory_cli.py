from typer.testing import CliRunner

from strato.services.ebs.cli.inventory import app
from strato.services.ebs.domains.inventory.checks import (
    EBSInventoryScanner,
    EBSInventoryScanType,
)
from strato.services.ebs.domains.inventory.views import EBSInventoryView

runner = CliRunner()


def test_scan_missing_output_flags():
    """Test that the command fails if neither --json nor --csv are provided."""
    result = runner.invoke(app, [])

    assert result.exit_code == 1
    assert "Error: Use --json or --csv" in result.output


def test_scan_with_json_and_region(mocker):
    """Test a successful invocation with --json and --region flags."""
    mock_run_scan = mocker.patch("strato.services.ebs.cli.inventory.run_scan")

    result = runner.invoke(app, ["--json", "--region", "us-west-2"])

    assert result.exit_code == 0
    mock_run_scan.assert_called_once_with(
        scanner_cls=EBSInventoryScanner,
        check_type=EBSInventoryScanType.VOLUMES,
        verbose=False,
        json_output=True,
        csv_output=False,
        failures_only=False,
        org_role=None,
        view_class=EBSInventoryView,
        region="us-west-2",
    )


def test_scan_with_csv_verbose_and_role(mocker):
    """Test a successful invocation with --csv, verbose, and an assumed role."""
    mock_run_scan = mocker.patch("strato.services.ebs.cli.inventory.run_scan")

    result = runner.invoke(
        app, ["--csv", "--verbose", "--org-role", "arn:aws:iam::123:role/audit"]
    )

    assert result.exit_code == 0
    mock_run_scan.assert_called_once_with(
        scanner_cls=EBSInventoryScanner,
        check_type=EBSInventoryScanType.VOLUMES,
        verbose=True,
        json_output=False,
        csv_output=True,
        failures_only=False,
        org_role="arn:aws:iam::123:role/audit",
        view_class=EBSInventoryView,
        region=None,
    )
