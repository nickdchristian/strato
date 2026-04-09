from typing import Annotated

import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.rds.domains.inventory.checks import (
    RDSInventoryScanner,
    RDSInventoryScanType,
)
from strato.services.rds.domains.inventory.views import RDSInventoryView

app = typer.Typer(help="RDS Inventory")
console_err = Console(stderr=True)


def create_scan_command(target_scan_type: RDSInventoryScanType, command_help_text: str):
    def command(
        ctx: typer.Context,
        verbose: Annotated[
            bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
        ] = False,
        json_output: Annotated[
            bool, typer.Option("--json", help="Output raw JSON")
        ] = False,
        csv_output: Annotated[bool, typer.Option("--csv", help="Output CSV")] = False,
        region: Annotated[
            str | None,
            typer.Option(
                "--region", help="Specific AWS Region to scan (e.g. us-east-1)"
            ),
        ] = None,
        org_role: Annotated[
            str | None,
            typer.Option(
                "--org-role", help="IAM role to assume for multi-account scan"
            ),
        ] = None,
    ):
        session = ctx.obj.get("session")
        account_id = ctx.obj.get("account_id")

        scan_code = run_scan(
            scanner_cls=RDSInventoryScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            org_role=org_role,
            view_class=RDSInventoryView,
            region=region,
            session=session,
            account_id=account_id,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    RDSInventoryScanType.INVENTORY: "Gather inventory of RDS Instances",
}

for scan_type in RDSInventoryScanType:
    cmd_name = scan_type.value.replace("_", "-").lower()
    if cmd_name == "inventory":
        cmd_name = "scan"

    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")
    app.command(cmd_name)(create_scan_command(scan_type, help_text))
