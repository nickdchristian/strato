from typing import Annotated

import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.rds.domains.reserved.checks import (
    RDSReservedInstanceScanner,
    RDSReservedScanType,
)
from strato.services.rds.domains.reserved.views import RDSReservedInstanceView

app = typer.Typer(help="RDS Reserved Instance Contracts")
console_err = Console(stderr=True)


@app.command("scan")
def scan(
    ctx: typer.Context,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Output raw JSON")
    ] = False,
    csv_output: Annotated[bool, typer.Option("--csv", help="Output CSV")] = False,
    region: Annotated[
        str | None, typer.Option("--region", help="Specific AWS Region to scan")
    ] = None,
    org_role: Annotated[
        str | None,
        typer.Option("--org-role", help="IAM role to assume for multi-account scan"),
    ] = None,
):
    """
    Scan for Purchased Reserved Instances (Active Contracts).
    """
    session = ctx.obj.get("session")
    account_id = ctx.obj.get("account_id")

    scan_code = run_scan(
        scanner_cls=RDSReservedInstanceScanner,
        check_type=RDSReservedScanType.RESERVED_INSTANCES,
        verbose=verbose,
        json_output=json_output,
        csv_output=csv_output,
        org_role=org_role,
        view_class=RDSReservedInstanceView,
        region=region,
        session=session,
        account_id=account_id,
    )

    if scan_code != 0:
        raise typer.Exit(scan_code)
