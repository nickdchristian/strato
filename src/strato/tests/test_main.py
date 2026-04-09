from unittest import mock

import typer
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from typer.testing import CliRunner

from strato.main import app

runner = CliRunner(mix_stderr=False)


# 1. Inject a dummy command into the app strictly for testing the global callback.
# This lets us verify that `ctx.obj` was successfully populated.
@app.command("dummy-test-cmd")
def dummy_test_cmd(ctx: typer.Context):
    print(f"Injected Account: {ctx.obj.get('account_id')}")


@mock.patch("strato.main.boto3.Session")
def test_main_callback_success(mock_session_cls):
    """
    Verify the happy path: Session is created, STS identity is fetched, context is set.
    """
    mock_session = mock.Mock()
    mock_sts = mock.Mock()

    # Mock the STS get_caller_identity response
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session.client.return_value = mock_sts
    mock_session_cls.return_value = mock_session

    # Invoke the dummy command with global options
    result = runner.invoke(
        app, ["--profile", "audit-profile", "--region", "us-east-1", "dummy-test-cmd"]
    )

    assert result.exit_code == 0
    assert "Injected Account: 123456789012" in result.stdout

    # Verify Boto3 was initialized with the exact global flags
    mock_session_cls.assert_called_once_with(
        profile_name="audit-profile", region_name="us-east-1"
    )


@mock.patch("strato.main.boto3.Session")
def test_main_callback_no_credentials(mock_session_cls):
    """Verify behavior when no AWS credentials are found."""
    mock_session_cls.side_effect = NoCredentialsError()

    result = runner.invoke(app, ["dummy-test-cmd"])

    assert result.exit_code == 1
    assert "No AWS credentials found" in result.stderr


@mock.patch("strato.main.boto3.Session")
def test_main_callback_expired_token(mock_session_cls):
    """Verify specific handling for expired STS tokens (ClientError)."""
    mock_session = mock.Mock()
    mock_sts = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_cls.return_value = mock_session

    # Generate a mocked Botocore ClientError
    error_response = {"Error": {"Code": "ExpiredToken", "Message": "Token is expired"}}
    mock_sts.get_caller_identity.side_effect = ClientError(
        error_response, "GetCallerIdentity"
    )

    result = runner.invoke(app, ["dummy-test-cmd"])

    assert result.exit_code == 1
    assert "AWS session expired (ExpiredToken)" in result.stderr


@mock.patch("strato.main.boto3.Session")
def test_main_callback_standard_client_error(mock_session_cls):
    """Verify fallback handling for other Botocore ClientErrors."""
    mock_session = mock.Mock()
    mock_sts = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_cls.return_value = mock_session

    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "You shall not pass"}
    }
    mock_sts.get_caller_identity.side_effect = ClientError(
        error_response, "GetCallerIdentity"
    )

    result = runner.invoke(app, ["dummy-test-cmd"])

    assert result.exit_code == 1
    assert "AWS Error:" in result.stderr
    assert "AccessDenied" in result.stderr


@mock.patch("strato.main.boto3.Session")
def test_main_callback_sso_error(mock_session_cls):
    """Verify SSO/Token retrieval error catching from generic BotoCoreErrors."""

    # Create a dummy exception class to simulate an SSO error
    class MockSSOError(BotoCoreError):
        fmt = "Failed to load SSO profile"

    mock_session_cls.side_effect = MockSSOError()

    result = runner.invoke(app, ["dummy-test-cmd"])

    assert result.exit_code == 1
    assert "SSO Token expired or invalid" in result.stderr


@mock.patch("strato.main.boto3.Session")
def test_main_callback_unexpected_error(mock_session_cls):
    """Verify generic fallback exception handler."""
    mock_session_cls.side_effect = ValueError("Something completely broken")

    result = runner.invoke(app, ["dummy-test-cmd"])

    assert result.exit_code == 1
    assert "Unexpected Error:" in result.stderr
    assert "Something completely broken" in result.stderr
