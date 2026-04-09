from unittest import mock

from typer.testing import CliRunner

from strato.services.rds.cli.reserved import app
from strato.services.rds.domains.reserved.checks import RDSReservedScanType

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


@mock.patch("strato.services.rds.cli.reserved.run_scan")
def test_reserved_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--csv"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == RDSReservedScanType.RESERVED_INSTANCES
