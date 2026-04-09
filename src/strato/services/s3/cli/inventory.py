from typing import Annotated

import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.s3.domains.inventory.checks import (
    S3InventoryScanner,
    S3InventoryScanType,
)
from strato.services.s3.domains.inventory.views import S3InventoryView

app = typer.Typer(help="S3 Inventory & Cost Analysis")
console_err = Console(stderr=True)


def create_scan_command(target_scan_type: S3InventoryScanType, command_help_text: str):
    def command(
        ctx: typer.Context,
        verbose: Annotated[
            bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
        ] = False,
        json_output: Annotated[
            bool, typer.Option("--json", help="Output raw JSON")
        ] = False,
        csv_output: Annotated[bool, typer.Option("--csv", help="Output CSV")] = False,
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
            scanner_cls=S3InventoryScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            org_role=org_role,
            view_class=S3InventoryView,
            region=None,  # S3 is global, so region remains None
            session=session,
            account_id=account_id,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    S3InventoryScanType.INVENTORY: "Gather an inventory of S3 Buckets",
}

CMD_NAME_MAP = {
    S3InventoryScanType.INVENTORY: "scan",
}

for scan_type in S3InventoryScanType:
    default_name = scan_type.value.replace("_", "-").lower()
    cmd_name = CMD_NAME_MAP.get(scan_type, default_name)

    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")

    app.command(cmd_name)(create_scan_command(scan_type, help_text))
