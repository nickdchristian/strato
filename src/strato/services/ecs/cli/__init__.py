import typer

from strato.services.ecs.cli import inventory

ecs_app = typer.Typer(help="EC2 Auditing & Inventory")
ecs_app.add_typer(inventory.app, name="inventory")
