"""
This is a SaltyRTC server implementation for Python 3.5.3+ using
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

__all__ = tuple(itertools.chain(
    ('bin', 'typing'),
    common.__all__,  # noqa
    events.__all__,  # noqa
    exception.__all__,  # noqa
    message.__all__,  # noqa
    protocol.__all__,  # noqa
    server.__all__,  # noqa
    task.__all__,  # noqa
    util.__all__,  # noqa
))

__author__ = 'Lennart Grahl <lennart.grahl@gmail.com>'
__status__ = 'Production'
__version__ = '4.2.0'
