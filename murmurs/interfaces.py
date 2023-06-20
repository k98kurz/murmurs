from __future__ import annotations
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CanJsonSerialize(Protocol):
    """Interface for classes that can serialize to and from json."""
    def to_json(self) -> str:
        """Return serialized instance data json."""
        ...

    @classmethod
    def from_json(cls, data: str) -> CanJsonSerialize:
        """Deserialize data from json and return instance."""
        ...


@runtime_checkable
class CanUnicast(Protocol):
    """Interface for classes that can handle unicast message sending."""
    def unicast(self, message: Any, dst: Any) -> bool:
        """Returns True if the message can be sent to the dst and False
            otherwise.
        """
        ...
