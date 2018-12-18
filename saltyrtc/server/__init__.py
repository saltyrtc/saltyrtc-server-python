"""
This is a SaltyRTC server implementation for Python 3.4+ using
:mod:`asyncio`.
"""
import itertools

# noinspection PyUnresolvedReferences
from .exception import *  # noqa
# noinspection PyUnresolvedReferences
from .common import *  # noqa
# noinspection PyUnresolvedReferences
from .message import *  # noqa
# noinspection PyUnresolvedReferences
from .protocol import *  # noqa
# noinspection PyUnresolvedReferences
from .server import *  # noqa
# noinspection PyUnresolvedReferences
from .util import *  # noqa
# noinspection PyUnresolvedReferences
from .events import *  # noqa

__all__ = tuple(itertools.chain(
    ('bin',),
    exception.__all__,  # noqa
    common.__all__,  # noqa
    message.__all__,  # noqa
    protocol.__all__,  # noqa
    server.__all__,  # noqa
    util.__all__,  # noqa
    events.__all__,  # noqa
))

__author__ = 'Lennart Grahl <lennart.grahl@gmail.com>'
__status__ = 'Production'
__version__ = '3.0.0'
