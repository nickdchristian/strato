import typer
from rich.console import Console

from strato.core.runner import run_scan
from strato.services.ebs.domains.inventory.checks import (
    EBSInventoryScanner,
    EBSInventoryScanType,
)
from strato.services.ebs.domains.inventory.views import EBSInventoryView

app = typer.Typer(help="EBS Volume Inventory & Audit")
console_err = Console(stderr=True)


@app.command("scan")
def scan(
    verbose: bool = False,
    json_output: bool = typer.Option(False, "--json"),
    csv_output: bool = typer.Option(False, "--csv"),
    region: str = typer.Option(None, "--region"),
    org_role: str = typer.Option(None, "--org-role"),
):
    if not (json_output or csv_output):
        console_err.print("[bold red]Error:[/bold red] Use --json or --csv")
        raise typer.Exit(1)

    run_scan(
        scanner_cls=EBSInventoryScanner,
        check_type=EBSInventoryScanType.VOLUMES,
        verbose=verbose,
        json_output=json_output,
        csv_output=csv_output,
        failures_only=False,
        org_role=org_role,
        view_class=EBSInventoryView,
        region=region,
    )
