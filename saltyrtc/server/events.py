import collections
import enum
from typing import (  # noqa
    Callable,
    Dict,
    List,
    Optional,
    Union,
)

try:
    from typing import Coroutine
except ImportError:
    # noinspection PyUnresolvedReferences,PyPackageRequirements
    from backports_abc import Coroutine

__all__ = (
    'DisconnectedData',
    'EventData',
    'EventCallback',
    'Event',
    'EventRegistry',
)


# Types
DisconnectedData = int
EventData = Union[
    None,  # `initiator-connected` / `responder-connected`
    DisconnectedData,
]
EventCallback = Callable[[str, Optional[str], EventData], Coroutine],


@enum.unique
class Event(enum.Enum):
    """
    Available event types that will be raised by the server and can be
    registered by the application.
    """
    initiator_connected = 'initiator-connected'
    responder_connected = 'responder-connected'
    disconnected = 'disconnected'


class EventRegistry:
    """
    Allows to register callbacks to be invoked in case a specific event
    has been raised by the server.

    A callback must be an `async` function. When it is being invoked,
    the following parameters need to be provided:
        - `path`: A `str` instance containing the path in hexadecimal
          representation an event is associated to or `None` if
          unavailable (which can only happen in case of a `disconnected`
          event).
        - `data`: Additional data associated to the event as
          described below.

    Additional data :class:`Event` to :class`EventData` mapping:
        - `initiator-connected`: `None`
        - `responder-connected`: `None`
        - `disconnected`: :class:`DisconnectedData`
    """
    events = collections.defaultdict(list)  # type: Dict[Event, List[EventCallback]]

    def register(self, event: Event, handler: EventCallback):
        """
        Register an event callback.
        """
        self.events[event].append(handler)

    def get_callbacks(self, event: Event) -> List[EventCallback]:
        """
        Return callbacks associated to a specific event.
        """
        return self.events[event]
