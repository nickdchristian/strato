from unittest import mock

from typer.testing import CliRunner

from strato.services.rds.cli.reserved import app
from strato.services.rds.domains.reserved.checks import RDSReservedScanType

runner = CliRunner(mix_stderr=False)


def invoke_scan(args):
    cmd = app.registered_commands[0].name if app.registered_commands else "scan"
    res = runner.invoke(app, [cmd] + args)
    if res.exit_code == 2:
        return runner.invoke(app, args)
    return res


@mock.patch("strato.services.rds.cli.reserved.run_scan")
def test_reserved_scan_success(mock_run_scan):
    mock_run_scan.return_value = 0
    result = invoke_scan(["--csv"])

    assert result.exit_code == 0
    args, kwargs = mock_run_scan.call_args
    assert kwargs["check_type"] == RDSReservedScanType.RESERVED_INSTANCES
