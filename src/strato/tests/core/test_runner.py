from io import StringIO
from typing import Any

from rich.console import Console

from strato.core.models import AuditResult, BaseScanner
from strato.core.runner import run_scan, scan_single_account


class FakeScanner(BaseScanner):
    @property
    def service_name(self) -> str:
        return "FakeService"

    def fetch_resources(self):
        return ["item"]

    def analyze_resource(self, resource: Any):
        return AuditResult("arn", "item", "us-east-1", self.account_id)


class GlobalFakeScanner(FakeScanner):
    is_global_service = True

    @property
    def service_name(self) -> str:
        return "GlobalFakeService"


class DummyEvaluator:
    """A fake evaluator that always scores 100 (CRITICAL)."""

    @classmethod
    def evaluate(cls, result: AuditResult) -> tuple[int, list[str]]:
        return 100, ["Dummy CRITICAL Finding"]


def test_scan_single_account_uses_region(mocker):
    mock_session_cls = mocker.patch("boto3.Session")

    scan_single_account(
        account_id="123",
        account_name="test",
        role_name=None,
        scanner_cls=FakeScanner,
        check_type="ALL",
        region="eu-central-1",
    )

    mock_session_cls.assert_called_with(region_name="eu-central-1")


def test_run_scan_propagates_region(mocker):
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123"}
    mocker.patch("boto3.client", return_value=mock_sts)

    mock_session_cls = mocker.patch("boto3.Session")
    mock_session_instance = mock_session_cls.return_value
    mock_session_instance.region_name = "us-east-1"

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = []
    mock_scanner_instance.service_name = "Fake"
    mocker.patch.object(FakeScanner, "__new__", return_value=mock_scanner_instance)

    run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        failures_only=False,
        region="us-west-2",
    )

    mock_session_cls.assert_called_with(region_name="us-west-2")


def test_run_scan_fails_fast_no_region(mocker):
    mock_session_cls = mocker.patch("boto3.Session")
    mock_session_instance = mock_session_cls.return_value
    mock_session_instance.region_name = None

    string_buffer = StringIO()
    mock_console = Console(file=string_buffer, force_terminal=True)
    mocker.patch("strato.core.runner.console_err", mock_console)

    exit_code = run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        failures_only=False,
        region=None,
    )

    assert exit_code == 1
    output = string_buffer.getvalue()
    assert "No AWS region specified" in output


def test_run_scan_global_service_defaults_region(mocker):
    """
    Ensures that a service marked is_global_service=True does NOT fail
    when no region is provided, and defaults to us-east-1.
    """
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123"}
    mocker.patch("boto3.client", return_value=mock_sts)

    mock_session_cls = mocker.patch("boto3.Session")

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
        failures_only=False,
        region=None,  # Explicitly None
    )

    assert exit_code == 0
    mock_session_cls.assert_called_with(region_name="us-east-1")


def test_run_scan_without_evaluator_is_pure_inventory(mocker):
    """Ensures that passing no evaluator results in a 0 score."""
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123"}
    mocker.patch("strato.core.runner.boto3.client", return_value=mock_sts)
    mocker.patch("strato.core.runner.boto3.Session")

    dummy_result = AuditResult(
        resource_arn="arn", resource_name="item", region="us-east-1", account_id="123"
    )

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = [dummy_result]
    mock_scanner_instance.service_name = "FakeService"
    mocker.patch.object(FakeScanner, "__new__", return_value=mock_scanner_instance)

    mock_presenter_cls = mocker.patch("strato.core.runner.AuditPresenter")

    run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        failures_only=False,
        region="us-east-1",
        evaluator_cls=None,
    )

    mock_presenter_cls.assert_called_once()
    args, _ = mock_presenter_cls.call_args
    results_passed_to_presenter = args[0]

    assert len(results_passed_to_presenter) == 1
    assert results_passed_to_presenter[0].status_score == 0
    assert len(results_passed_to_presenter[0].findings) == 0


def test_run_scan_with_evaluator_applies_scores(mocker):
    """Ensures that passing an evaluator successfully mutates the scores."""
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123"}
    mocker.patch("strato.core.runner.boto3.client", return_value=mock_sts)
    mocker.patch("strato.core.runner.boto3.Session")

    dummy_result = AuditResult(
        resource_arn="arn", resource_name="item", region="us-east-1", account_id="123"
    )

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = [dummy_result]
    mock_scanner_instance.service_name = "FakeService"
    mocker.patch.object(FakeScanner, "__new__", return_value=mock_scanner_instance)

    mock_presenter_cls = mocker.patch("strato.core.runner.AuditPresenter")

    run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        failures_only=False,
        region="us-east-1",
        evaluator_cls=DummyEvaluator,
    )

    mock_presenter_cls.assert_called_once()
    args, _ = mock_presenter_cls.call_args
    results_passed_to_presenter = args[0]

    assert len(results_passed_to_presenter) == 1
    assert results_passed_to_presenter[0].status_score == 100
    assert results_passed_to_presenter[0].findings == ["Dummy CRITICAL Finding"]


def test_run_scan_failures_only_filter(mocker):
    """Ensures the failures_only flag correctly filters the results."""
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "123"}
    mocker.patch("strato.core.runner.boto3.client", return_value=mock_sts)
    mocker.patch("strato.core.runner.boto3.Session")

    dummy_result = AuditResult(
        resource_arn="arn", resource_name="item", region="us-east-1", account_id="123"
    )

    mock_scanner_instance = mocker.Mock()
    mock_scanner_instance.scan.return_value = [dummy_result]
    mock_scanner_instance.service_name = "FakeService"
    mocker.patch.object(FakeScanner, "__new__", return_value=mock_scanner_instance)

    mock_presenter_cls = mocker.patch("strato.core.runner.AuditPresenter")

    run_scan(
        scanner_cls=FakeScanner,
        check_type="ALL",
        verbose=False,
        json_output=True,
        csv_output=False,
        failures_only=True,
        region="us-east-1",
        evaluator_cls=None,
    )

    mock_presenter_cls.assert_called_once()
    args, _ = mock_presenter_cls.call_args
    results_passed_to_presenter = args[0]

    assert len(results_passed_to_presenter) == 0
