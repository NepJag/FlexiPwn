from __future__ import annotations

import typer

from flexipwn.layer4.cli import daemon as daemon_mod
from flexipwn.layer4.cli import participant as participant_mod
from flexipwn.layer4.cli import run as run_mod
from flexipwn.layer4.cli import scenario as scenario_mod
from flexipwn.layer4.db.session import get_engine, init_db

app = typer.Typer(
    help="FlexiPwn — plataforma educativa de ciberseguridad ofensiva",
    no_args_is_help=True,
)

app.add_typer(scenario_mod.app, name="scenario")
app.add_typer(participant_mod.app, name="participant")
app.add_typer(run_mod.app, name="run")
app.add_typer(daemon_mod.app, name="daemon")


@app.callback(invoke_without_command=True)
def _init(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        return
    engine = get_engine()
    init_db(engine)
