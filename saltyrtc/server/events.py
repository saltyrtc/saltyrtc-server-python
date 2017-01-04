import collections
from collections.abc import Coroutine
from enum import (
    Enum,
    unique,
)
from typing import List

__all__ = ('Event',)


@unique
class Event(Enum):
    INITIATOR_CONNECTED = 'initiator-connected'
    RESPONDER_CONNECTED = 'responder-connected'


class EventRegistry:
    events = collections.defaultdict(list)  # type: Dict[Event, List[Coroutine]]

    def register(self, event: Event, handler: Coroutine):
        self.events[event].append(handler)

    def get_callbacks(self, event: Event) -> List[Coroutine]:
        return self.events[event]
