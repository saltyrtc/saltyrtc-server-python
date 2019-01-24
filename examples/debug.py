import asyncio
import os
import ssl  # noqa
import sys
from typing import Any  # noqa
from typing import Coroutine  # noqa
from typing import List  # noqa
from typing import Optional

import logbook.more

import saltyrtc.server
from saltyrtc.server.typing import ServerSecretPermanentKey  # noqa


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    try:
        return os.environ[name]
    except KeyError:
        return default


def require_env(name: str) -> str:
    value = env(name)
    if value is None:
        print("Missing '{}' env variable".format(name))
        sys.exit(1)
    return value


def main() -> None:
    """
    Run the SaltyRTC server until Ctrl+C has been pressed.
    """
    loop = asyncio.get_event_loop()

    # Create SSL context
    ssl_context = None  # type: Optional[ssl.SSLContext]
    if env('SALTYRTC_DISABLE_TLS') != 'yes-and-i-know-what-im-doing':
        ssl_context = saltyrtc.server.create_ssl_context(
            certfile=require_env('SALTYRTC_TLS_CERT'),
            keyfile=require_env('SALTYRTC_TLS_KEY'),
            dh_params_file=require_env('SALTYRTC_DH_PARAMS'),
        )

    # Get permanent key
    permanent_keys = None  # type: Optional[List[ServerSecretPermanentKey]]
    if env('SALTYRTC_DISABLE_SERVER_PERMANENT_KEY') != 'yes-and-i-know-what-im-doing':
        permanent_keys = [saltyrtc.server.load_permanent_key(
            require_env('SALTYRTC_SERVER_PERMANENT_KEY'))]

    # Start server
    port_str = env('SALTYRTC_PORT', '8765')
    assert port_str is not None
    port = int(port_str)
    coroutine = saltyrtc.server.serve(
        ssl_context, permanent_keys, port=port
    )  # type: Coroutine[Any, Any, saltyrtc.server.Server]
    server = loop.run_until_complete(coroutine)

    # Wait until Ctrl+C has been pressed
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Wait until server is closed and close the event loop
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    # Enable asyncio debug logging
    os.environ['PYTHONASYNCIODEBUG'] = '1'

    # Enable logging
    saltyrtc.server.enable_logging(level=logbook.TRACE, redirect_loggers={
        'asyncio': logbook.DEBUG,
        'websockets': logbook.DEBUG,
    })

    # Run 'main'
    logging_handler = logbook.more.ColorizedStderrHandler()
    with logging_handler.applicationbound():
        main()
