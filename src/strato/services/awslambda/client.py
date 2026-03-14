import logging
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


def safe_aws_call(default: Any, safe_error_codes: list[str] | None = None) -> Callable:
    if safe_error_codes is None:
        safe_error_codes = []

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            client_instance = args[0] if args else None
            acc = getattr(client_instance, "account_id", "Unknown")

            context = (
                kwargs.get("FunctionName")
                or kwargs.get("function_name")
                or (args[1] if len(args) > 1 else "")
            )

            func_name = getattr(func, "__name__", "unknown_callable")
            prefix = f"[{acc}]" + (f"[{context}]" if context else "")

            logger.debug(f"{prefix} {func_name}")

            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")

                if error_code in safe_error_codes:
                    logger.debug(f"{prefix} Safely caught expected: {error_code}")
                    return cast(T, default)

                if error_code not in ["AccessDeniedException", "InvalidParameter"]:
                    logger.warning(
                        "%s AWS Error in %s: %s - %s", prefix, func_name, error_code, e
                    )
                return cast(T, default)
            except Exception as e:
                logger.error("%s Unexpected error in %s: %s", prefix, func_name, e)
                return cast(T, default)

        return wrapper

    return decorator


class LambdaClient:
    def __init__(
        self, session: boto3.Session | None = None, account_id: str = "Unknown"
    ):
        self.retry_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
        self.session = session or boto3.Session()
        self.account_id = account_id
        self._client = self.session.client("lambda", config=self.retry_config)
        self._cw_client = self.session.client("cloudwatch", config=self.retry_config)

    def list_functions(self) -> list[dict[str, Any]]:
        logger.debug(f"[{self.account_id}] Paginating through all Lambda functions...")
        paginator = self._client.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        logger.debug(
            f"[{self.account_id}] Successfully retrieved "
            f"{len(functions)} Lambda functions."
        )
        return functions
