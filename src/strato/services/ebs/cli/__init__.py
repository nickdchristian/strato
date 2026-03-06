import typer

from strato.services.ebs.cli import inventory

ebs_app = typer.Typer(help="EBS Auditing & Inventory")
ebs_app.add_typer(inventory.app, name="inventory")
