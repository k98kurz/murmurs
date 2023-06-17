from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class CanSendMessages(Protocol):
    def send(self, message: bytes, to: bytes) -> None:
        ...


@runtime_checkable
class CanRouteMessages(Protocol):
    def route(self, message: bytes, to: bytes) -> None:
        ...


@runtime_checkable
class CanElectRoot(Protocol):
    def current_root(self) -> Any:
        ...

    def check_new_root(self, condition: Any) -> bool:
        ...

    def elect_new_root(self, new_root: Any) -> bytes:
        ...


@runtime_checkable
class CanCreateSpanningTree(Protocol):
    def has_parent(self) -> bool:
        ...

    def check_new_parent(self, parent: Any) -> bool:
        ...

    def set_parent(self, parent: Any) -> None:
        ...

    def has_children(self) -> bool:
        ...

    def check_new_Child(self, child: Any) -> bool:
        ...

    def add_child(self, child: Any) -> bool:
        ...


@runtime_checkable
class CanCalculateAddress(Protocol):
    def calculate_address(self, coordinates: list[Any]) -> bytes:
        ...


@runtime_checkable
class CanAssignAddress(Protocol):
    def assign_address(self, target: Any, address: bytes) -> bytes:
        ...
