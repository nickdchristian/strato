import logging

from botocore.exceptions import ClientError

from strato.core.aws import safe_aws_call


class DummyClient:
    """Mock AWS client class to test account_id extraction."""

    def __init__(self):
        self.account_id = "123456789012"


def generate_client_error(code: str, message: str = "Mocked AWS Error") -> ClientError:
    """Helper to generate botocore ClientErrors with specific codes."""
    error_response = {"Error": {"Code": code, "Message": message}}
    return ClientError(error_response, "MockOperation")


def test_safe_aws_call_success():
    """Verify that a successful function returns its actual value."""

    @safe_aws_call(default="fallback")
    def mock_func(self, **kwargs):
        return "success"

    client = DummyClient()
    result = mock_func(client, some_arg="value")

    assert result == "success"


def test_context_extraction_single_key(caplog):
    """Verify context extraction when context_key is a string."""
    caplog.set_level(logging.DEBUG)

    @safe_aws_call(default=None, context_key="bucket_name")
    def mock_func(self, **kwargs):
        return True

    client = DummyClient()
    mock_func(client, bucket_name="my-test-bucket")

    # Verify the prefix contains both account ID and the context value
    assert "[123456789012][my-test-bucket] mock_func" in caplog.text


def test_context_extraction_list_of_keys(caplog):
    """Verify context extraction when context_key is a list of strings."""
    caplog.set_level(logging.DEBUG)

    @safe_aws_call(default=None, context_key=["VolumeId", "volume_id"])
    def mock_func(self, **kwargs):
        return True

    client = DummyClient()
    # Pass the second key in the list to ensure it falls back correctly
    mock_func(client, volume_id="vol-0abcd1234")

    assert "[123456789012][vol-0abcd1234] mock_func" in caplog.text


def test_context_extraction_missing_key(caplog):
    """Verify behavior when the requested context key is not provided."""
    caplog.set_level(logging.DEBUG)

    @safe_aws_call(default=None, context_key="bucket_name")
    def mock_func(self, **kwargs):
        return True

    client = DummyClient()
    mock_func(client, unrelated_kwarg="foo")

    # Should only log the account ID without failing
    assert "[123456789012] mock_func" in caplog.text


def test_safe_error_code_caught(caplog):
    """Verify that an expected AWS error returns default and logs as DEBUG."""
    caplog.set_level(logging.DEBUG)

    @safe_aws_call(default={}, safe_error_codes=["NoSuchBucket"])
    def mock_func(self):
        raise generate_client_error("NoSuchBucket")

    client = DummyClient()
    result = mock_func(client)

    assert result == {}
    assert "Safely caught expected: NoSuchBucket" in caplog.text
    assert "WARNING" not in caplog.text


def test_quiet_error_code_suppressed(caplog):
    """Verify that default quiet errors do not trigger WARNING logs."""
    caplog.set_level(logging.WARNING)

    @safe_aws_call(default=False)
    def mock_func(self):
        raise generate_client_error("AccessDeniedException")

    client = DummyClient()
    result = mock_func(client)

    assert result is False
    # Since it's a quiet error, nothing should be logged at the WARNING level
    assert "AWS Error" not in caplog.text


def test_custom_quiet_error_code(caplog):
    """Verify that custom quiet errors suppress WARNING logs."""
    caplog.set_level(logging.WARNING)

    @safe_aws_call(default=False, quiet_error_codes=["ThrottlingException"])
    def mock_func(self):
        raise generate_client_error("ThrottlingException")

    client = DummyClient()
    result = mock_func(client)

    assert result is False
    assert "AWS Error" not in caplog.text


def test_unexpected_client_error_logs_warning(caplog):
    """Verify that unhandled ClientErrors log a WARNING and return default."""
    caplog.set_level(logging.WARNING)

    @safe_aws_call(default=[])
    def mock_func(self):
        raise generate_client_error("InternalFailure")

    client = DummyClient()
    result = mock_func(client)

    assert result == []
    assert "AWS Error in mock_func: InternalFailure" in caplog.text


def test_generic_exception_logs_error(caplog):
    """Verify that standard Python exceptions log an ERROR and return default."""
    caplog.set_level(logging.ERROR)

    @safe_aws_call(default="failed")
    def mock_func(self):
        raise ValueError("Something went terribly wrong")

    client = DummyClient()
    result = mock_func(client)

    assert result == "failed"
    assert "Unexpected error in mock_func: Something went terribly wrong" in caplog.text


def test_standalone_function_without_client_class(caplog):
    """
    Verify the decorator doesn't crash if used on a function without an account_id.
    """
    caplog.set_level(logging.DEBUG)

    @safe_aws_call(default=None)
    def standalone_func():
        return True

    standalone_func()

    # Should gracefully default to [Unknown]
    assert "[Unknown] standalone_func" in caplog.text
