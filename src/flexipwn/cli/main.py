from __future__ import annotations

import atexit

import typer

from flexipwn.cli import participant as participant_mod
from flexipwn.cli import run as run_mod
from flexipwn.cli import scenario as scenario_mod
from flexipwn.db.session import get_engine, init_db
from flexipwn.layer4 import cli as demo_cli_mod

app = typer.Typer(
    help="FlexiPwn — plataforma educativa de ciberseguridad ofensiva",
    no_args_is_help=True,
)

app.add_typer(scenario_mod.app, name="scenario")
app.add_typer(participant_mod.app, name="participant")
app.add_typer(run_mod.app, name="run")
app.add_typer(demo_cli_mod.demo_app, name="demo")


@app.callback(invoke_without_command=True)
def _init(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        return
    engine = get_engine()
    init_db(engine)


def _cleanup_super_monitor() -> None:
    try:
        from flexipwn.core.super_monitor import _instance
        if _instance is not None:
            _instance.stop()
    except Exception:
        pass


atexit.register(_cleanup_super_monitor)
