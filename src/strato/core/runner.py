import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError
from rich.console import Console
from rich.logging import RichHandler

from strato.core.models import BaseScanner, InventoryRecord
from strato.core.presenter import InventoryPresenter

console_err = Console(stderr=True)


def setup_logging(verbose: bool):
    log_level = logging.DEBUG if verbose else logging.ERROR
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console_err, rich_tracebacks=True)],
    )

    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_org_accounts(session: boto3.Session) -> list[dict]:
    """Fetches AWS Organization accounts using the globally authenticated session."""
    org_client = session.client("organizations")
    accounts = []
    paginator = org_client.get_paginator("list_accounts")

    try:
        for page in paginator.paginate():
            for acc in page["Accounts"]:
                if acc["Status"] == "ACTIVE":
                    accounts.append({"Id": acc["Id"], "Name": acc["Name"]})
    except ClientError as e:
        console_err.print(f"[bold red]Error listing accounts:[/bold red] {e}")
        sys.exit(1)
    except NoRegionError:
        console_err.print(
            "[bold red]Error:[/bold red] No AWS region specified. "
            "Please set [green]AWS_DEFAULT_REGION[/green] or use the "
            "[green]--region[/green] flag."
        )
        sys.exit(1)

    return accounts


def assume_role_session(
    account_id: str,
    role_name: str,
    parent_session: boto3.Session,
    region: str | None = None,
) -> boto3.Session | None:
    """Assumes a role in a target account using the parent session's credentials."""
    sts_client = parent_session.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="StratoAuditSession"
        )
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region or parent_session.region_name,
        )
    except ClientError:
        return None
    except NoRegionError:
        return None


def scan_single_account(
    account_id: str,
    account_name: str,
    role_name: str | None,
    scanner_cls: type[BaseScanner],
    check_type: str,
    parent_session: boto3.Session,
    region: str | None = None,
) -> tuple[list[InventoryRecord], str | None]:
    try:
        if role_name:
            session = assume_role_session(account_id, role_name, parent_session, region)
            if not session:
                return [], f"Access Denied: {account_id} ({account_name})"
        else:
            # Fallback to parent session if no role assumption is needed
            session = parent_session

        scanner = scanner_cls(
            check_type=check_type, session=session, account_id=account_id
        )
        return scanner.scan(silent=True), None

    except NoRegionError:
        return [], f"Configuration Error: No Region specified for {account_id}"
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        return [], f"AWS Error: {account_id} - {error_code}: {e}"
    except Exception as e:
        return [], f"Unexpected Error: {account_id} - {str(e)}"


def _execute_multi_account_scan(
    scanner_cls: type[BaseScanner],
    check_type: str,
    org_role: str,
    session: boto3.Session,
    region: str | None = None,
) -> list[InventoryRecord]:
    if not scanner_cls.is_global_service:
        if not region and not session.region_name:
            console_err.print(
                "[bold red]"
                "Configuration Error:"
                "[/bold red] You must specify a region for multi-account scans.\n"
                "Use the [green]--region[/green] flag or set the "
                "[green]AWS_DEFAULT_REGION[/green] environment variable."
            )
            sys.exit(1)

    if scanner_cls.is_global_service and not region:
        region = "us-east-1"

    accounts = get_org_accounts(session)
    all_results = []
    skipped = []

    console_err.print(
        f"[bold blue]Scanning {len(accounts)} accounts "
        f"with role '{org_role}'...[/bold blue]"
    )

    with console_err.status(
        "[bold yellow]Running Multi-Account Scan...", spinner="dots"
    ):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(
                    scan_single_account,
                    acc["Id"],
                    acc["Name"],
                    org_role,
                    scanner_cls,
                    check_type,
                    session,
                    region,
                ): acc
                for acc in accounts
            }

            for future in as_completed(futures):
                results, error = future.result()
                if error:
                    skipped.append(error)
                else:
                    all_results.extend(results)

    if skipped:
        console_err.print(
            f"\n[bold yellow]Skipped {len(skipped)} accounts:[/bold yellow]"
        )
        for msg in skipped:
            console_err.print(f"  • {msg}", style="yellow")
        console_err.print("")

    return all_results


def _execute_single_scan(
    scanner_cls: type[BaseScanner],
    check_type: str,
    region: str | None,
    silent_mode: bool,
    session: boto3.Session,
    account_id: str,
) -> list[InventoryRecord] | int:
    """Handles the execution using the injected context session."""
    try:
        # Override the session's region cleanly if a specific region was passed down
        # and it differs from the globally set region
        effective_region = region or session.region_name

        if scanner_cls.is_global_service and not effective_region:
            effective_region = "us-east-1"

        if not scanner_cls.is_global_service and not effective_region:
            raise NoRegionError()

        # If a region override is needed, recreate the session using the same creds
        if effective_region and effective_region != session.region_name:
            creds = session.get_credentials().get_frozen_credentials()
            session = boto3.Session(
                aws_access_key_id=creds.access_key,
                aws_secret_access_key=creds.secret_key,
                aws_session_token=creds.token,
                region_name=effective_region,
            )

        scanner = scanner_cls(
            check_type=check_type, session=session, account_id=account_id
        )
        return scanner.scan(silent=silent_mode)

    except NoRegionError:
        console_err.print(
            "\n[bold red]Configuration Error:[/bold red] No AWS region specified."
        )
        console_err.print(
            "Please provide a region using the "
            "[green]--region[/green] flag or set the "
            "[green]AWS_DEFAULT_REGION[/green] environment variable.\n"
        )
        return 1
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        console_err.print(
            f"[bold red]AWS Error:[/bold red] {account_id} - {error_code}: {e}"
        )
        return 1
    except Exception as e:
        console_err.print(f"[bold red]Unexpected Error:[/bold red] {account_id} - {e}")
        return 1


def _render_output(
    presenter: InventoryPresenter,
    scanner_cls: type[BaseScanner],
    check_type: str,
    all_results: list[InventoryRecord],
    json_output: bool,
    csv_output: bool,
    org_role: str | None,
) -> int:
    """Handles the terminal output branching logic."""
    if json_output:
        presenter.print_json()
    elif csv_output:
        presenter.print_csv()
    else:
        if all_results:
            title_prefix = "Organization " if org_role else ""
            presenter.print_table(
                title=f"{title_prefix}{scanner_cls(check_type).service_name}"
            )
        else:
            console_err.print("[bold blue]No Results Found[/bold blue]")

    return 0


def run_scan(
    scanner_cls: type[BaseScanner],
    check_type: str,
    verbose: bool,
    json_output: bool,
    csv_output: bool,
    org_role: str | None = None,
    view_class: Any = None,
    region: str | None = None,
    session: boto3.Session | None = None,
    account_id: str | None = None,
) -> int:
    setup_logging(verbose)

    # Fallback logic for when tests/local functions call run_scan directly
    if session is None:
        session = boto3.Session(region_name=region)

    # Strictly type-cast account_id to satisfy static analysis
    resolved_account_id: str = "Unknown"
    if account_id is not None:
        resolved_account_id = str(account_id)
    else:
        try:
            sts = session.client("sts")
            fetched_account = sts.get_caller_identity().get("Account")
            resolved_account_id = str(fetched_account) if fetched_account else "Unknown"
        except (ClientError, NoCredentialsError, NoRegionError):
            resolved_account_id = "Unknown"

    if org_role:
        scan_output = _execute_multi_account_scan(
            scanner_cls, check_type, org_role, session, region
        )
    else:
        silent_mode = json_output or csv_output
        scan_output = _execute_single_scan(
            scanner_cls, check_type, region, silent_mode, session, resolved_account_id
        )

    if isinstance(scan_output, int):
        return scan_output

    all_results = scan_output

    presenter = InventoryPresenter(
        all_results,
        check_type=check_type,
        view_class=view_class,
    )

    return _render_output(
        presenter,
        scanner_cls,
        check_type,
        all_results,
        json_output,
        csv_output,
        org_role,
    )
