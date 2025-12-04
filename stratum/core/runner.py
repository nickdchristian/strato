import sys
import logging
from typing import Type
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console

from stratum.core.models import AuditResult
from stratum.core.presenter import AuditPresenter
from stratum.core.scanner import BaseScanner

console = Console()


def setup_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def run_scan(
    scanner_cls: Type[BaseScanner],
    result_cls: Type[AuditResult],
    check_type: str,
    verbose: bool,
    fail_on_risk: bool,
    json_output: bool,
    csv_output: bool,
    failures_only: bool,
):
    """
    Universal Runner.
    Can be used by S3 Security, EC2 Costs, RDS Compliance, etc.
    """
    setup_logging(verbose)
    scanner = scanner_cls(check_type=check_type)

    try:
        results = scanner.scan(silent=(json_output or csv_output))
    except NoCredentialsError:
        console.print(
            "[bold red]Error:[/bold red] No AWS credentials found. Please configure your environment."
        )
        sys.exit(1)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in [
            "InvalidClientTokenId",
            "SignatureDoesNotMatch",
            "AuthFailure",
            "ExpiredToken",
        ]:
            console.print(
                "[bold red]Error:[/bold red] Invalid AWS credentials. Please check your keys/token."
            )
        else:
            console.print(f"[bold red]Error:[/bold red] AWS API failed: {error_code}")
        sys.exit(1)

    if failures_only:
        results = [r for r in results if r.has_risk]

    presenter = AuditPresenter(results, result_type=result_cls, check_type=check_type)

    if json_output:
        presenter.print_json()
    elif csv_output:
        presenter.print_csv()
    else:
        title_suffix = " [Failures Only]" if failures_only else ""
        presenter.print_table(title=f"{scanner.service_name}{title_suffix}")

    if fail_on_risk and any(result.has_risk for result in results):
        sys.exit(1)
