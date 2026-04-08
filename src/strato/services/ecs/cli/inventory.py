import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.ecs.domains.inventory.checks import (
    ECSInventoryScanner,
    ECSInventoryScanType,
)
from strato.services.ecs.domains.inventory.views import ECSInventoryView

app = typer.Typer(help="ECS Inventory")
console_err = Console(stderr=True)


def create_scan_command(target_scan_type: ECSInventoryScanType, command_help_text: str):
    def command(
        verbose: bool = False,
        json_output: bool = typer.Option(False, "--json", help="Output raw JSON"),
        csv_output: bool = typer.Option(False, "--csv", help="Output CSV"),
        region: str | None = typer.Option(
            None, "--region", help="Specific AWS Region to scan"
        ),
        org_role: str | None = typer.Option(
            None, "--org-role", help="IAM role to assume for multi-account scan"
        ),
    ):
        scan_code = run_scan(
            scanner_cls=ECSInventoryScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            org_role=org_role,
            view_class=ECSInventoryView,
            region=region,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    ECSInventoryScanType.INVENTORY: "Gather inventory of ECS Clusters and Services",
}

for scan_type in ECSInventoryScanType:
    cmd_name = scan_type.value.replace("_", "-").lower()
    if cmd_name == "inventory":
        cmd_name = "scan"

    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")
    app.command(cmd_name)(create_scan_command(scan_type, help_text))
