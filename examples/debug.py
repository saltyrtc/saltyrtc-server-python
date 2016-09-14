import os
import sys
import asyncio

import logbook.more

import saltyrtc


def env(name, default=None):
    return os.environ.get(name, default)


def require_env(name):
    value = env(name)
    if value is None:
        print("Missing '{}' env variable".format(name))
        sys.exit(1)
    return value


def main():
    """
    Run the SaltyRTC server until Ctrl+C has been pressed.
    """
    loop = asyncio.get_event_loop()

    # Create SSL context
    ssl_context = saltyrtc.util.create_ssl_context(
        certfile=require_env('SALTYRTC_TLS_CERT'),
        keyfile=require_env('SALTYRTC_TLS_KEY'),
    )

    # Start server
    coroutine = saltyrtc.serve(ssl_context, port=int(env('SALTYRTC_PORT', '8765')))
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
    saltyrtc.util.enable_logging(level=logbook.TRACE, redirect_loggers={
        'asyncio': logbook.DEBUG,
        'websockets': logbook.DEBUG,
    })

    # Run 'main'
    logging_handler = logbook.more.ColorizedStderrHandler()
    with logging_handler.applicationbound():
        main()
