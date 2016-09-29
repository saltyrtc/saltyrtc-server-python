"""
TODO: Describe project
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
from .client import *  # noqa
# noinspection PyUnresolvedReferences
from .server import *  # noqa
# noinspection PyUnresolvedReferences
from .util import *  # noqa

__all__ = tuple(itertools.chain(
    exception.__all__,  # noqa
    common.__all__,  # noqa
    message.__all__,  # noqa
    protocol.__all__,  # noqa
    client.__all__,  # noqa
    server.__all__,  # noqa
    util.__all__,  # noqa
))

__author__ = 'Lennart Grahl <lennart.grahl@gmail.com>'
__status__ = 'Development'
__version__ = '0.9.9'
