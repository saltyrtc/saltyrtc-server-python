import collections
import enum
from typing import List

try:
    from collections.abc import Coroutine
except ImportError:  # python 3.4
    from backports_abc import Coroutine

__all__ = ('Event',)


@enum.unique
class Event(enum.Enum):
    initiator_connected = 'initiator-connected'
    responder_connected = 'responder-connected'
    disconnected = 'disconnected'


class EventRegistry:
    events = collections.defaultdict(list)  # type: Dict[Event, List[Coroutine]]

    def register(self, event: Event, handler: Coroutine):
        self.events[event].append(handler)

    def get_callbacks(self, event: Event) -> List[Coroutine]:
        return self.events[event]
