from typing import Annotated

import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.awslambda.domains.inventory.checks import (
    LambdaInventoryScanner,
    LambdaInventoryScanType,
)
from strato.services.awslambda.domains.inventory.views import LambdaInventoryView

app = typer.Typer(help="Lambda Inventory & Audit")
console_err = Console(stderr=True)


def create_scan_command(
    target_scan_type: LambdaInventoryScanType, command_help_text: str
):
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
            str | None, typer.Option("--region", help="Specific AWS Region to scan")
        ] = None,
        org_role: Annotated[
            str | None,
            typer.Option(
                "--org-role", help="IAM role to assume for multi-account scan"
            ),
        ] = None,
    ):
        if not (json_output or csv_output):
            console_err.print(
                "\n[bold red]Error:[/bold red] Lambda inventory data is too wide for "
                "table output."
            )
            console_err.print(
                "Please specify a structured format: "
                "[green]--json[/green] or [green]--csv[/green]\n"
            )
            raise typer.Exit(1)

        session = ctx.obj.get("session")
        account_id = ctx.obj.get("account_id")

        scan_code = run_scan(
            scanner_cls=LambdaInventoryScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            org_role=org_role,
            view_class=LambdaInventoryView,
            region=region,
            session=session,
            account_id=account_id,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    LambdaInventoryScanType.INVENTORY: "Gather a inventory of Lambda Functions",
}

CMD_NAME_MAP = {
    LambdaInventoryScanType.INVENTORY: "scan",
}

for scan_type in LambdaInventoryScanType:
    default_name = scan_type.value.replace("_", "-").lower()
    cmd_name = CMD_NAME_MAP.get(scan_type, default_name)

    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")

    app.command(cmd_name)(create_scan_command(scan_type, help_text))
