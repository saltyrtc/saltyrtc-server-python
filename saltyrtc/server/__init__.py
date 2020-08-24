"""
This is a SaltyRTC server implementation for Python 3.6.1+ using
:mod:`asyncio`.
"""
import itertools

from .common import *  # noqa
from .events import *  # noqa
from .exception import *  # noqa
from .message import *  # noqa
from .protocol import *  # noqa
from .server import *  # noqa
from .task import *  # noqa
from .util import *  # noqa

from . import common, events, exception, message, protocol, server, task, util

__all__ = tuple(itertools.chain(
    ('bin', 'typing'),
    common.__all__,
    events.__all__,
    exception.__all__,
    message.__all__,
    protocol.__all__,
    server.__all__,
    task.__all__,
    util.__all__,
))

__author__ = 'Lennart Grahl <lennart.grahl@gmail.com>'
__status__ = 'Production'
__version__ = '5.0.1'
