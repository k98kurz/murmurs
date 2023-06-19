from __future__ import annotations
from .errors import vert, tert
from .interfaces import CanJsonSerialize
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Callable
from uuid import uuid4
import json


class SpanningTreeEvent(Enum):
    BEFORE_SET_PARENT = auto()
    AFTER_SET_PARENT = auto()
    BEFORE_ADD_CHILD = auto()
    AFTER_ADD_CHILD = auto()
    BEFORE_REMOVE_CHILD = auto()
    AFTER_REMOVE_CHILD = auto()
    BEFORE_ADD_NEIGHBOR = auto()
    AFTER_ADD_NEIGHBOR = auto()
    BEFORE_REMOVE_NEIGHBOR = auto()
    AFTER_REMOVE_NEIGHBOR = auto()


@dataclass
class LocalTree:
    id: bytes = field(default_factory=lambda: uuid4().bytes)
    node_id: bytes = field(default=b'')
    parent_id: bytes = field(default = b'')
    child_ids: list[bytes] = field(default_factory=list)
    neighbor_ids: set[bytes] = field(default_factory=set)
    hooks: dict[str, Callable] = field(default_factory=dict)
    parent_data: CanJsonSerialize = field(default=None)
    child_data: dict[bytes, CanJsonSerialize] = field(default_factory=dict)
    neighbor_data: dict[bytes, CanJsonSerialize] = field(default_factory=dict)

    def set_hook(self, event: SpanningTreeEvent,
                 func: Callable[[SpanningTreeEvent, dict], dict]) -> None:
        """Sets a hook for an event. Takes the SpanningTreeEvent event
            and a Callable func as args. The func should take a
            SpanningTreeEvent event and a dict event data, and it should
            return the dict event data to be passed on to subsequent
            hooks; it may change the dict event data.
        """
        self.hooks[event.name] = func

    def add_hook(self, event: SpanningTreeEvent,
                 func: Callable[[SpanningTreeEvent, dict], dict]) -> None:
        """Adds a hook for an event. Takes the SpanningTreeEvent event
            and a Callable func as args. The func should take a
            SpanningTreeEvent event and a dict event data, and it should
            return the dict event data to be passed on to subsequent
            hooks; it may change the dict event data.
        """
        tert(type(event) is SpanningTreeEvent, 'event must be a SpanningTreeEvent')
        if event.name not in self.hooks:
            return self.set_hook(event, func)

        current_func = self.hooks[event.name]
        intermediate = lambda event, data: func(event, current_func(event, data))
        self.hooks[event.name] = intermediate

    def invoke_hook(self, event: SpanningTreeEvent, data: dict) -> None:
        """Invokes the hooks if present for the event, passing data."""
        tert(type(event) is SpanningTreeEvent, 'event must be SpanningTreeEvent')
        if event.name in self.hooks:
            self.hooks[event.name](event.name, {**data, 'tree': self})

    def set_parent(self, parent_id: bytes,
                   parent_data: dict|CanJsonSerialize = None) -> None:
        """Sets the parent and calls any hooks for the BEFORE_SET_PARENT
            and then AFTER_SET_PARENT events.
        """
        tert(type(parent_id) is bytes, 'parent_id must be bytes')
        tert(isinstance(parent_data, dict)
             or isinstance(parent_data, CanJsonSerialize)
             or parent_data is None,
             'parent_data must be dict or instance implementing CanJsonSerialize')
        self.invoke_hook(
            SpanningTreeEvent.BEFORE_SET_PARENT,
            {
                'parent_id': parent_id,
                'parent_data': parent_data,
                'current_parent_id': self.parent_id,
                'current_parent_data': self.parent_data
            }
        )

        self.parent_id = parent_id
        self.parent_data = parent_data

        self.invoke_hook(
            SpanningTreeEvent.AFTER_SET_PARENT,
            {
                'parent_id': parent_id,
                'parent_data': parent_data
            }
        )

    def add_child(self, child_id: bytes,
                  child_data: dict|CanJsonSerialize = None) -> None:
        """Adds a child and calls any hooks for the BEFORE_ADD_CHILD and
            AFTER_ADD_CHILD events.
        """
        tert(type(child_id) is bytes, 'child_id must be bytes')
        vert(len(child_id) > 0, 'child_id must not be empty')
        tert(isinstance(child_data, dict)
             or isinstance(child_data, CanJsonSerialize)
             or child_data is None,
             'child_data must be dict or instance implementing CanJsonSerialize')

        self.invoke_hook(
            SpanningTreeEvent.BEFORE_ADD_CHILD,
            {
                'child_id': child_id,
                'child_data': child_data,
                'child_ids': self.child_ids,
                'all_child_data': self.child_data
            }
        )

        if child_id not in self.child_ids:
            # reuse indices of former children
            if b'' in self.child_ids:
                index = self.child_ids.index(b'')
                self.child_ids[index] = child_id
            else:
                self.child_ids.append(child_id)
        if child_data:
            self.child_data[child_id] = child_data

        self.invoke_hook(
            SpanningTreeEvent.AFTER_ADD_CHILD,
            {
                'child_id': child_id,
                'child_ids': self.child_ids,
                'child_data': self.child_data
            }
        )

    def remove_child(self, child_id: bytes) -> None:
        """Removes a child and calls any hooks for the
            BEFORE_REMOVE_CHILD and AFTER_REMOVE_CHILD events.
        """
        tert(type(child_id) is bytes, 'child_id must be bytes')
        vert(len(child_id) > 0, 'child_id must not be empty')

        child_data = self.child_data[child_id] if child_id in self.child_data else None

        self.invoke_hook(
            SpanningTreeEvent.BEFORE_REMOVE_CHILD,
            {
                'child_id': child_id,
                'child_ids': self.child_ids,
                'child_data': child_data,
                'all_child_data': self.child_data
            }
        )

        if child_id in self.child_ids:
            # preserve indices
            self.child_ids[self.child_ids.index(child_id)] = b''
        if child_id in self.child_data:
            del self.child_data[child_id]

        self.invoke_hook(
            SpanningTreeEvent.AFTER_REMOVE_CHILD,
            {
                'child_id': child_id,
                'child_ids': self.child_ids,
                'child_data': child_data,
                'all_child_data': self.child_data
            }
        )

    def add_neighbor(self, neighbor_id: bytes,
                     neighbor_data: dict|CanJsonSerialize = None) -> None:
        """Adds a neighbor and calls any hooks for the
            BEFORE_ADD_NEIGHBOR and AFTER_ADD_NEIGHBOR events.
        """
        tert(type(neighbor_id) is bytes, 'neighbor_id must be bytes')
        tert(isinstance(neighbor_data, dict)
             or isinstance(neighbor_data, CanJsonSerialize)
             or neighbor_data is None,
             'neighbor_data must be dict or instance implementing CanJsonSerialize')

        self.invoke_hook(
            SpanningTreeEvent.BEFORE_ADD_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.neighbor_ids,
                'all_neighbor_data': self.neighbor_data
            }
        )

        self.neighbor_ids.add(neighbor_id)
        if neighbor_data:
            self.neighbor_data[neighbor_id] = neighbor_data

        self.invoke_hook(
            SpanningTreeEvent.AFTER_ADD_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.neighbor_ids,
                'all_neighbor_data': self.neighbor_data
            }
        )

    def remove_neighbor(self, neighbor_id: bytes) -> None:
        """Removes a neighbor and calls any hooks for the
            BEFORE_REMOVE_NEIGHBOR and AFTER_REMOVE_NEIGHBOR events.
        """
        tert(type(neighbor_id) is bytes, 'neighbor_id must be bytes')

        neighbor_data = self.neighbor_data[neighbor_id] \
            if neighbor_id in self.neighbor_data \
            else None

        self.invoke_hook(
            SpanningTreeEvent.BEFORE_REMOVE_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.neighbor_ids,
                'all_neighbor_data': self.neighbor_data
            }
        )

        if neighbor_id in self.neighbor_ids:
            self.neighbor_ids.remove(neighbor_id)
        if neighbor_id in self.neighbor_data:
            del self.neighbor_data[neighbor_id]

        self.invoke_hook(
            SpanningTreeEvent.AFTER_REMOVE_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.neighbor_ids,
                'all_neighbor_data': self.neighbor_data
            }
        )

    def to_json(self) -> str:
        """Serialize instance data to json."""
        parent_data = self.parent_data
        if parent_data and isinstance(parent_data, CanJsonSerialize):
            parent_data = parent_data.to_json()
        child_data = {
            cid.hex(): data.to_json()
                if isinstance(data, CanJsonSerialize)
                else data
            for cid, data in self.child_data.items()
        }
        neighbor_data = {
            nid.hex(): data.to_json()
                if isinstance(data, CanJsonSerialize)
                else data
            for nid, data in self.neighbor_data.items()
        }

        return json.dumps({
            'id': self.id.hex(),
            'parent_id': self.parent_id.hex(),
            'child_ids': [c.hex() for c in self.child_ids],
            'neighbor_ids': [n.hex() for n in self.neighbor_ids],
            'parent_data': parent_data,
            'child_data': child_data,
            'neighbor_data': neighbor_data,
        })

    @classmethod
    def from_json(cls, data: str|bytes, /, *,
                  parent_data_type: type[CanJsonSerialize] = None,
                  child_data_type: type[CanJsonSerialize] = None,
                  neighbor_data_type: type[CanJsonSerialize] = None) -> LocalTree:
        """Deserialize the instance data from json. Uses parent_data_type,
            child_data_type, and neighbor_data_type if provided to
            deserialize parent_data, child_data, and neighbor_data,
            respectively.
        """
        unpacked = json.loads(data)
        parent_data = unpacked['parent_data']
        if parent_data_type and parent_data:
            parent_data = parent_data_type(parent_data)

        child_data = {
            bytes.fromhex(cid): data
            for cid, data in unpacked['child_data'].items()
        }
        if child_data_type and child_data:
            child_data = {
                cid: child_data_type(data)
                for cid, data in child_data.items()
            }

        neighbor_data = {
            bytes.fromhex(nid): data
            for nid, data in unpacked['neighbor_data'].items()
        }
        if neighbor_data_type and neighbor_data:
            neighbor_data = {
                nid: neighbor_data_type(data)
                for nid, data in neighbor_data.items()
            }

        return cls(
            id=bytes.fromhex(unpacked['id']),
            parent_id=bytes.fromhex(unpacked['parent_id']),
            child_ids=[bytes.fromhex(c) for c in unpacked['child_ids']],
            neighbor_ids=set([bytes.fromhex(o) for o in unpacked['neighbor_ids']]),
            parent_data=parent_data,
            child_data=child_data,
            neighbor_data=neighbor_data
        )
