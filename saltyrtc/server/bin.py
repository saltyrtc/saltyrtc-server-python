"""
The command line interface for the SaltyRTC signalling server.
"""
import os

import click

from . import __version__ as _version
from . import server  # noqa
from . import (
    aio_serve,
    enable_logging,
)


@click.group()
@click.pass_context
def cli(ctx):
    """
    Command Line Interface. Use --help for details.
    """
    ctx.obj = {}


@cli.command(short_help='Show version information.', help="""
Show the current version of the SaltyRTC signalling server.
""")
def version():
    click.echo('Version: {}'.format(_version))


@cli.command(short_help='Start the signalling server.', help="""
Start the SaltyRTC signalling server. CERT represents the path to a
file in PEM format containing the SSL certificate of the server.""")
@click.argument('cert', type=click.Path(exists=True))
@click.option('-k', '--keyfile', type=click.Path(exists=True), help="""
Path to a file that contains the private key. Will be read from
CERTFILE if not present.
""")
@aio_serve
def serve(**arguments):
    certfile = arguments.get('cert')  # noqa
    keyfile = arguments.get('keyfile', None)  # noqa
    raise NotImplementedError
    # yield from server.start_server(
    #     certfile=certfile, keyfile=keyfile
    # )


def main():
    # TODO: Read keys from export if set (see restartable.py)
    # TODO: Add *logging* option
    # noinspection PyPackageRequirements
    import logbook.more

    # Enable asyncio debug logging
    os.environ['PYTHONASYNCIODEBUG'] = '1'

    # Enable logging
    enable_logging(level=logbook.TRACE, redirect_loggers={
        'asyncio': logbook.DEBUG,
        'websockets': logbook.DEBUG,
    })

    # Run 'main'
    logging_handler = logbook.more.ColorizedStderrHandler()
    with logging_handler.applicationbound():
        try:
            cli()
        except Exception as exc:
            click.echo('An error occurred:', err=True)
            click.echo(exc, err=True)
            raise
