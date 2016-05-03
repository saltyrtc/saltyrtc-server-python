import os
import asyncio

import logbook
import logbook.more

from saltyrtc.server import util, start_server


class ColorizedStdErrHandler(logbook.more.ColorizedStderrHandler):
    """
    Adds a color to the NOTICE level to be able to distinguish
    NOTICE and DEBUG levels.
    """
    def get_color(self, record):
        """Returns the color for this record."""
        if record.level >= logbook.ERROR:
            return 'red'
        elif record.level >= logbook.NOTICE:
            return 'yellow'
        elif record.level >= logbook.INFO:
            return 'blue'
        else:
            return 'lightgray'


def main():
    """
    Run the SaltyRTC server until Ctrl+C has been pressed.
    """
    loop = asyncio.get_event_loop()

    # Start server
    server = loop.run_until_complete(start_server(
        certfile='PATH_TO_YOUR_SSL_CERTIFICATE',
        keyfile='PATH_TO_YOUR_PRIVATE_KEY',
        host='127.0.0.1',
        port=8765,
    ))

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
    util.enable_logging(level=logbook.TRACE, redirect_loggers={
        'asyncio': logbook.DEBUG,
        'websockets': logbook.DEBUG,
    })

    # Run 'main'
    logging_handler = ColorizedStdErrHandler()
    with logging_handler.applicationbound():
        main()
