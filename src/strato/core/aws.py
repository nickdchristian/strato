import logging
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


def safe_aws_call(
    default: Any,
    safe_error_codes: list[str] | None = None,
    quiet_error_codes: list[str] | None = None,
    context_key: str | list[str] | None = None,
) -> Callable:
    """
    Executes an AWS SDK call, catching ClientErrors and returning a default value.

    :param default: The value to return if a caught error occurs.
    :param safe_error_codes: List of AWS Error Codes that are expected and
        handled gracefully.
    :param quiet_error_codes: List of AWS Error Codes that shouldn't trigger a
        warning log.
    :param context_key: Kwarg key(s) to extract for logging context (e.g.,
        'VolumeId', 'Bucket').
    """
    safe_errors = safe_error_codes or []
    quiet_errors = quiet_error_codes or ["AccessDeniedException", "InvalidParameter"]

    if isinstance(context_key, str):
        context_keys = [context_key]
    else:
        context_keys = context_key or []

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            client_instance = args[0] if args else None
            acc = getattr(client_instance, "account_id", "Unknown")

            context_val = ""
            for key in context_keys:
                if key in kwargs:
                    context_val = kwargs[key]
                    break

            func_name = getattr(func, "__name__", "unknown_callable")
            prefix = f"[{acc}]" + (f"[{context_val}]" if context_val else "")

            logger.debug(f"{prefix} {func_name}")

            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")

                if error_code in safe_errors:
                    logger.debug(f"{prefix} Safely caught expected: {error_code}")
                    return cast(T, default)

                if error_code not in quiet_errors:
                    logger.warning(
                        "%s AWS Error in %s: %s - %s", prefix, func_name, error_code, e
                    )
                return cast(T, default)
            except Exception as e:
                logger.error("%s Unexpected error in %s: %s", prefix, func_name, e)
                return cast(T, default)

        return wrapper

    return decorator
