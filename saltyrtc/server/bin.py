"""
The command line interface for the SaltyRTC signalling server.
"""
import asyncio
import enum
import os
import signal
import stat
from typing import Coroutine  # noqa
from typing import List  # noqa
from typing import Optional  # noqa
from typing import Sequence  # noqa
from typing import Any

import click
import libnacl.public

from . import (
    __version__ as _version,
    server,
    util,
)
from .typing import ServerSecretPermanentKey  # noqa
from .typing import LogbookLevel

__all__ = (
    'cli',
    'version',
    'generate',
    'serve',
    'main',
)


def _echo_deprecated(message: str) -> None:
    click.echo(click.style('DeprecationWarning: {}'.format(message), fg='yellow'))


def _h(text: str) -> str:
    """
    For some reason, :mod:`click` does not strip new line characters
    from helps in :func:`click.option` (although it does strip them
    from helps for :func:`click.command`). So, we have to do it
    ourselves.
    """
    return text.replace('\n', ' ')


def _get_logging_level(verbosity: int) -> LogbookLevel:
    import logbook
    return LogbookLevel({
        1: logbook.CRITICAL,
        2: logbook.ERROR,
        3: logbook.WARNING,
        4: logbook.NOTICE,
        5: logbook.INFO,
        6: logbook.DEBUG,
        7: logbook.TRACE,
    }[verbosity])


class _ErrorCode(enum.IntEnum):
    safety_error = 2
    import_error = 3
    repeated_keys = 4


_logging_levels = 7


@click.group()
@click.option('-v', '--verbosity', type=click.IntRange(0, _logging_levels),
              default=0, help="Logging verbosity.")
@click.option('-c', '--colored', is_flag=True, help='Colourise logging output.')
@click.pass_context
def cli(ctx: click.Context, verbosity: int, colored: bool) -> None:
    """
    Command Line Interface. Use --help for details.
    """
    if verbosity > 0:
        try:
            # noinspection PyUnresolvedReferences
            import logbook.more
        except ImportError:
            click.echo('Please install saltyrtc.server[logging] for logging support.',
                       err=True)
            ctx.exit(code=_ErrorCode.import_error)

        # Translate logging level
        level = _get_logging_level(verbosity)

        # Enable asyncio debug logging if verbosity is high enough
        # noinspection PyUnboundLocalVariable
        if level <= logbook.DEBUG:
            os.environ['PYTHONASYNCIODEBUG'] = '1'

        # Enable logging
        util.enable_logging(level=level, redirect_loggers={
            'asyncio': level,
            'websockets': level,
        })

        # Get handler class
        if colored:
            handler_class = logbook.more.ColorizedStderrHandler
        else:
            handler_class = logbook.StderrHandler

        # Set up logging handler
        handler = handler_class(level=level)
        handler.push_application()
        ctx.obj['logging_handler'] = handler


@cli.command(short_help='Show version information.', help="""
Show the current version of the SaltyRTC signalling server and the
implemented protocol versions.
""")
def version() -> None:
    click.echo('Version: {}'.format(_version))
    click.echo('Protocols: {}'.format(server.Server.subprotocols))


@cli.command(short_help='Generate a new server permanent key pair.', help="""
Generate a new permanent key pair for the server and write the private key to
the respective KEY_FILE.
""")
@click.argument('KEY_FILE', type=click.Path(writable=True, dir_okay=False))
def generate(key_file: str) -> None:
    # Generate key pair
    key_pair = libnacl.public.SecretKey()

    # Write hex-encoded private key to file using proper permissions (0o400)
    perm_other = stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
    perm_group = stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP
    current_umask = os.umask(perm_other | perm_group)
    with open(key_file, 'wb') as file:
        file.write(key_pair.hex_sk())
    os.umask(current_umask)

    # Print public key
    click.echo('Public permanent key: {}'.format(key_pair.hex_pk().decode('ascii')))


@cli.command(short_help='Start the signalling server.', help="""
Start the SaltyRTC signalling server. A HUP signal will restart the
server and reload the TLS certificate, the TLS private key and the
private permanent key of the server.""")
@click.option('-tc', '--tlscert', type=click.Path(exists=True), help=_h("""
Path to a PEM file that contains the TLS certificate."""))
@click.option('-sc', '--sslcert', type=click.Path(exists=True), help=_h("""
Deprecated alias of --tlscert."""))
@click.option('-tk', '--tlskey', type=click.Path(exists=True), help=_h("""
Path to a PEM file that contains the TLS private key. Will be read from
the TLS certificate file if not present."""))
@click.option('-sk', '--sslkey', type=click.Path(exists=True), help=_h("""
Deprecated alias of --tlskey."""))
@click.option('-dhp', '--dhparams', type=click.Path(exists=True), help=_h("""
Path to a PEM file that contains Diffie-Hellman parameters. Required
for DH(E) and ECDH(E) support."""))
@click.option('-k', '--key', type=click.Path(), multiple=True, help=_h("""
Path to a or a hex-encoded private permanent key of the server (e.g.
a NaCl private key). You can provide more than one key. The first key
provided will be used as the primary key."""))
@click.option('-h', '--host', help='Bind to a specific host.')
@click.option('-p', '--port', default=443, help='Listen on a specific port.')
@click.option('-l', '--loop', type=click.Choice(['asyncio', 'uvloop']), default='asyncio',
              help="Use a specific asyncio-compatible event loop. Defaults to 'asyncio'.")
@click.pass_context
def serve(ctx: click.Context, **arguments: Any) -> None:
    # Get arguments
    ssl_cert = arguments.get('sslcert', None)  # type: Optional[str]
    ssl_key = arguments.get('sslkey', None)  # type: Optional[str]
    tls_cert = arguments.get('tlscert', None) or ssl_cert  # type: Optional[str]
    tls_key = arguments.get('tlskey', None) or ssl_key  # type: Optional[str]
    dh_params = arguments.get('dhparams', None)  # type: Optional[str]
    keys_str = arguments['key']  # type: Sequence[str]
    host = arguments.get('host')  # type: Optional[str]
    port = arguments['port']  # type: int
    loop_str = arguments['loop']  # type: str
    safety_off = os.environ.get('SALTYRTC_SAFETY_OFF') == 'yes-and-i-know-what-im-doing'

    # Deprecation warning
    if ssl_cert is not None or ssl_key is not None:
        _echo_deprecated(('The options -sc, --sslcert and -sk, --sslkey are deprecated. '
                          'Use -tc, --tlscert and -tk, --tlskey instead.'))

    # Make sure the user provides cert & keys or has safety turned off
    if tls_cert is None or len(keys_str) == 0:
        if safety_off:
            click.echo(('It is RECOMMENDED to use SaltyRTC with both a TLS '
                       'certificate and a server permanent key!'), err=True)
        else:
            click.echo(('It is REQUIRED to provide a TLS certificate and a server '
                        'permanent key unless the environment variable '
                        "'SALTYRTC_SAFETY_OFF' is set to "
                        "'yes-and-i-know-what-im-doing'"), err=True)
            ctx.exit(code=_ErrorCode.safety_error)

    # Create SSL context
    ssl_context = None
    if tls_cert is not None:
        ssl_context = util.create_ssl_context(
            certfile=tls_cert, keyfile=tls_key, dh_params_file=dh_params)

    # Get private permanent keys of the server
    keys = [util.load_permanent_key(key)
            for key in keys_str]  # type: List[ServerSecretPermanentKey]

    # Validate permanent keys
    # Note: The permanent keys will be checked in the server coroutine but we don't want
    #       to look stupid.
    if len(keys) != len({key.pk for key in keys}):
        click.echo('At least one permanent key has been supplied more than once',
                   err=True)
        ctx.exit(code=_ErrorCode.repeated_keys)

    # Set event loop policy
    if loop_str == 'uvloop':
        try:
            # noinspection PyUnresolvedReferences
            import uvloop
        except ImportError:
            click.echo("Cannot use event loop 'uvloop', make sure it is installed.",
                       err=True)
            ctx.exit(code=_ErrorCode.import_error)
        # noinspection PyUnboundLocalVariable
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    # Get event loop
    loop = asyncio.get_event_loop()  # type: asyncio.AbstractEventLoop

    while True:
        # Run the server
        click.echo('Starting')
        if len(keys) > 0:
            primary_key, *secondary_keys = keys
            click.echo('Primary public permanent key: {}'.format(
                primary_key.hex_pk().decode('ascii')))
            for i, key in enumerate(secondary_keys, start=1):
                click.echo('Secondary key #{}: {}'.format(
                    i, key.hex_pk().decode('ascii')))
        coroutine = server.serve(
            ssl_context, keys,
            host=host, port=port, loop=loop
        )  # type: Coroutine[Any, Any, server.Server]
        server_ = loop.run_until_complete(coroutine)

        # Restart server on HUP signal
        restart_signal = asyncio.Future(loop=loop)  # type: asyncio.Future[None]

        def _restart_signal_handler() -> None:
            restart_signal.set_result(None)

        # Register restart server routine
        try:
            loop.add_signal_handler(signal.SIGHUP, _restart_signal_handler)
        except RuntimeError:
            click.echo('Cannot restart on SIGHUP, signal handler could not be added.')

        # Wait until Ctrl+C has been pressed
        click.echo('Started')
        try:
            loop.run_until_complete(restart_signal)
        except KeyboardInterrupt:
            click.echo()

        # Remove the signal handler
        loop.remove_signal_handler(signal.SIGHUP)

        # Close the server
        click.echo('Stopping')
        server_.close()
        loop.run_until_complete(server_.wait_closed())
        click.echo('Stopped')

        # Stop?
        if not restart_signal.done():
            restart_signal.cancel()
            break

    # Close loop
    loop.close()


def main() -> None:
    obj = {'logging_handler': None}
    try:
        cli(obj=obj, auto_envvar_prefix='SALTYRTC_SERVER')
    except Exception as exc:
        click.echo('An error occurred:', err=True)
        click.echo(exc, err=True)
        raise
    finally:
        try:
            import logbook  # noqa
        except ImportError:
            pass
        else:
            logging_handler = obj['logging_handler']  # type: Optional[logbook.Handler]
            if logging_handler is not None:
                logging_handler.pop_application()


if __name__ == '__main__':
    main()
