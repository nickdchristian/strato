from io import StringIO
from typing import Any

from rich.console import Console

from strato.core.models import BaseScanner, InventoryRecord
from strato.core.runner import run_scan, scan_single_account


class FakeScanner(BaseScanner):
    @property
    def service_name(self) -> str:
        return "FakeService"

    def fetch_resources(self):
        return ["item"]

    def analyze_resource(self, resource: Any):
        return InventoryRecord(
            resource_arn="arn",
            resource_name="item",
            region="us-east-1",
            account_id=self.account_id,
            details={},
        )


class GlobalFakeScanner(FakeScanner):
    is_global_service = True

    @property
    def service_name(self) -> str:
        return "GlobalFakeService"


def test_scan_single_account_uses_region(mocker):
    mock_session_cls = mocker.patch("strato.core.runner.boto3.Session")
    mock_parent_session = mocker.Mock()

    # Mock STS assume_role response so session creation succeeds
    mock_parent_session.client.return_value.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "fake-ak",
            "SecretAccessKey": "fake-sk",
            "SessionToken": "fake-token",
        }
    }

    scan_single_account(
        account_id="123",
        account_name="test",
        role_name="AuditRole",
        scanner_cls=FakeScanner,
        check_type="ALL",
        parent_session=mock_parent_session,  # Injected per new signature
        region="eu-central-1",
    )

    # Verify the session is instantiated with assumed credentials and proper region
    mock_session_cls.assert_called_with(
        aws_access_key_id="fake-ak",
        aws_secret_access_key="fake-sk",
        aws_session_token="fake-token",
        region_name="eu-central-1",
    )


def test_run_scan_propagates_region(mocker):
    mock_session = mocker.Mock()
    mock_session.region_name = "us-west-2"

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = []
    mock_scanner_instance.service_name = "Fake"
    mock_scanner_cls = mocker.patch.object(
        FakeScanner, "__new__", return_value=mock_scanner_instance
    )

    run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        region="us-west-2",
        session=mock_session,
        account_id="123",
    )

    # Verify the scanner was instantiated with the injected session and account_id
    mock_scanner_cls.assert_called_once()
    _, kwargs = mock_scanner_cls.call_args
    assert kwargs.get("session") == mock_session
    assert kwargs.get("account_id") == "123"


def test_run_scan_fails_fast_no_region(mocker):
    mock_session = mocker.Mock()
    mock_session.region_name = None

    string_buffer = StringIO()
    mock_console = Console(file=string_buffer, force_terminal=True)
    mocker.patch("strato.core.runner.console_err", mock_console)

    exit_code = run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        region=None,
        session=mock_session,
        account_id="123",
    )

    assert exit_code == 1
    output = string_buffer.getvalue()
    assert "No AWS region specified" in output


def test_run_scan_global_service_defaults_region(mocker):
    mocker.patch("strato.core.runner.boto3.Session")
    mock_session = mocker.Mock()
    mock_session.region_name = None

    # Mock the credentials retrieval block that happens when overriding regions
    mock_creds = mocker.Mock()
    mock_creds.access_key = "fake-ak"
    mock_creds.secret_key = "fake-sk"
    mock_creds.token = "fake-tok"
    mock_session.get_credentials.return_value.get_frozen_credentials.return_value = (
        mock_creds
    )

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = []
    mock_scanner_instance.service_name = "GlobalFake"
    mocker.patch.object(
        GlobalFakeScanner, "__new__", return_value=mock_scanner_instance
    )

    exit_code = run_scan(
        scanner_cls=GlobalFakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        region=None,
        session=mock_session,
        account_id="123",
    )

    assert exit_code == 0


def test_run_scan_routes_to_presenter(mocker):
    mock_session = mocker.Mock()
    # Match the region to prevent triggering the boto3 session override logic
    mock_session.region_name = "us-east-1"

    dummy_record = InventoryRecord(
        resource_arn="arn", resource_name="item", region="us-east-1", account_id="123"
    )

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = [dummy_record]
    mock_scanner_instance.service_name = "FakeService"
    mocker.patch.object(FakeScanner, "__new__", return_value=mock_scanner_instance)

    exit_code = run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        region="us-east-1",
        session=mock_session,
        account_id="123",
    )

    assert exit_code == 0
