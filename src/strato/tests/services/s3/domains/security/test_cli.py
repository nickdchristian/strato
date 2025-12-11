from unittest.mock import patch

from typer.testing import CliRunner

from strato.services.s3.cli.security import app

runner = CliRunner()


def test_cli_all_command_structure():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(
            app, ["all", "--verbose", "--fail-on-risk", "--org-role", "MyRole"]
        )

        assert result.exit_code == 0
        assert mock_run.called

        args = mock_run.call_args[0]
        # args mapping: (scanner_cls, result_cls, check_type, verbose,
        # fail_on_risk, json, csv, failures, org_role)
        # verbose is index 3
        assert args[3] is True
        # fail_on_risk is index 4
        assert args[4] is True
        # org_role is index 8 (last arg)
        assert args[8] == "MyRole"


def test_cli_encryption_defaults():
    with patch("strato.services.s3.cli.security.run_scan") as mock_run:
        result = runner.invoke(app, ["encryption"])

        assert result.exit_code == 0
        scan_type = mock_run.call_args[0][2]
        assert scan_type == "encryption"
        assert mock_run.call_args[0][8] is None
