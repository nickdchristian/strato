import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.ec2.domains.inventory.checks import (
    EC2InventoryScanner,
    EC2InventoryScanType,
)
from strato.services.ec2.domains.inventory.views import EC2InventoryView

app = typer.Typer(help="EC2 Inventory & Audit")
console_err = Console(stderr=True)


def create_scan_command(target_scan_type: EC2InventoryScanType, command_help_text: str):
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
            scanner_cls=EC2InventoryScanner,
            check_type=target_scan_type,
            verbose=verbose,
            json_output=json_output,
            csv_output=csv_output,
            org_role=org_role,
            view_class=EC2InventoryView,
            region=region,
        )

        if scan_code != 0:
            raise typer.Exit(scan_code)

    command.__doc__ = command_help_text
    return command


HELP_TEXT_MAP = {
    EC2InventoryScanType.INVENTORY: "Gather a comprehensive inventory of EC2 Instances",
}

CMD_NAME_MAP = {
    EC2InventoryScanType.INVENTORY: "scan",
}

for scan_type in EC2InventoryScanType:
    default_name = scan_type.value.replace("_", "-").lower()
    cmd_name = CMD_NAME_MAP.get(scan_type, default_name)

    help_text = HELP_TEXT_MAP.get(scan_type, f"Run {cmd_name} scan.")

    app.command(cmd_name)(create_scan_command(scan_type, help_text))
