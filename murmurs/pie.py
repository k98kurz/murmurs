from __future__ import annotations
from .errors import tert, vert, UnicastException
from .interfaces import CanJsonSerialize, CanUnicast
from .spanningtree import LocalTree
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from enum import Enum, auto
from hashlib import sha256
from math import ceil, floor, log2
from secrets import token_bytes
from typing import Callable
from uuid import uuid4
import json
import struct


class PIEEvent(Enum):
    RECEIVE_MESSAGE = auto()
    SEND_MESSAGE = auto()
    ROUTE_MESSAGE = auto()
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


class PIEMsgType(Enum):
    PACKET = 0
    HELLO = 1
    ECHO = 2
    TRACE_ROUTE = 3
    SET_ROOT = 4
    OFFER_ASSIGNMENT = 5
    ACCEPT_ASSIGNMENT = 6
    ANNOUNCE_ASSIGNMENT = 7


@dataclass
class PIEMessage:
    msg_type: PIEMsgType
    treeid: bytes
    dst: list[int]
    src: list[int]
    bifurcations: list[list[int]]
    body: bytes
    last_hop: list[int] = field(default=None)

    def encode_header(self, use_big_coords: bool = False) -> bytes:
        """Serialize header information to bytes."""
        if use_big_coords:
            src = encode_big_coordinates(self.src)
            dst = encode_big_coordinates(self.dst)
            bifurcations = [encode_big_coordinates(b) for b in self.bifurcations]
        else:
            src = encode_coordinates(self.src)
            dst = encode_coordinates(self.dst)
            bifurcations = [encode_coordinates(b) for b in self.bifurcations]

        bifurcations = struct.pack(
            '!B' + ''.join(['B' for _ in bifurcations]) +
            ''.join([f'{len(b)}s' for b in bifurcations]),
            len(bifurcations),
            *[len(b) for b in bifurcations],
            *[b for b in bifurcations]
        )

        return struct.pack(
            f'!BB{len(self.treeid)}sB{len(dst)}sB{len(src)}s{len(bifurcations)}s',
            self.msg_type.value,
            len(self.treeid),
            self.treeid,
            len(dst),
            dst,
            len(src),
            src,
            bifurcations
        )

    def to_bytes(self, use_big_coords: bool = False) -> bytes:
        """Serialize message to bytes."""
        header = self.encode_header(use_big_coords)

        return struct.pack(
            f'!H{len(header)}sH{len(self.body)}s',
            len(header),
            header,
            len(self.body),
            self.body
        )

    @staticmethod
    def decode_header(header: bytes, use_big_coords: bool = False) -> tuple:
        """Decode header fields from bytes."""
        msg_type, treeid_len, header = struct.unpack(
            f'!BB{len(header)-2}s',
            header
        )
        treeid, dst_len, header = struct.unpack(
            f'!{treeid_len}sB{len(header)-1-treeid_len}s',
            header
        )
        dst, src_len, header = struct.unpack(
            f'!{dst_len}sB{len(header)-1-dst_len}s',
            header
        )
        src, bifurcations = struct.unpack(
            f'!{src_len}s{len(header)-src_len}s',
            header
        )
        n_bifs, bifurcations = struct.unpack(
            f'!B{len(bifurcations)-1}s',
            bifurcations
        )
        bif_sizes = []
        bifs = []
        for _ in range(n_bifs):
            bif_len, bifurcations = struct.unpack(
                f'!B{len(bifurcations)-1}s',
                bifurcations
            )
            bif_sizes.append(bif_len)
        for bif_len in bif_sizes:
            bif, bifurcations = struct.unpack(
                f'!{bif_len}s{len(bifurcations)-bif_len}s',
                bifurcations
            )
            bifs.append(bif)
        if use_big_coords:
            dst = decode_big_coordinates(dst)
            src = decode_big_coordinates(src)
            bifurcations = [decode_big_coordinates(b) for b in bifs]
        else:
            dst = decode_coordinates(dst)
            src = decode_coordinates(src)
            bifurcations = [decode_coordinates(b) for b in bifs]

        return (
            PIEMsgType(msg_type),
            treeid,
            dst,
            src,
            bifurcations
        )

    @classmethod
    def from_bytes(cls, data: bytes, use_big_coords: bool = False) -> PIEMessage:
        """Deserialize a message from bytes."""
        header_len, _ = struct.unpack(f'!H{len(data)-2}s', data)
        _, header, body_len, body = struct.unpack(
            f'!H{header_len}sH{len(data)-header_len-4}s',
            data
        )
        vert(len(body) == body_len, 'message body length mismatch')
        msg_type, treeid, dst, src, bifurcations = cls.decode_header(header, use_big_coords)
        return cls(msg_type, treeid, dst, src, bifurcations, body)


_functions = {
    'sign': None,
    'check_sig': None,
    'elect_root': None,
    'send_message': None,
}


def set_sign_function(func: Callable[[bytes, bytes], bytes]) -> None:
    """Sets a function for signing messages. Function must take the
        private key bytes and message bytes as arguments and return the
        signature bytes.
    """
    tert(callable(func), 'func must be Callable[[bytes, bytes], bytes]')
    _functions['sign'] = func


def set_checksig_function(func: Callable[[bytes, bytes, bytes], bool]) -> None:
    """Sets a function for checking signatures. Function must take the
        public key bytes, message bytes, and signature bytes as args and
        return True if the signature is valid for the public key and
        message or False otherwise.
    """
    tert(callable(func), 'func must be Callable[[bytes, bytes, bytes], bool]')
    _functions['check_sig'] = func


def set_elect_root_func(func: Callable[[bytes, bytes, int], bool]) -> None:
    """Sets a function for electing a root. Function must take the bytes
        ID of the current root, the bytes ID of the candidate node, and
        int locality level as args and return True if the candidate
        should be elected to replace the current root or False otherwise.
    """
    tert(callable(func), 'func must be Callable[[bytes, bytes, int], bool]')
    _functions['elect_root'] = func


def set_send_message_func(func: Callable[[PIEMessage], None]) -> None:
    """Sets a function for sending a message. Function must take the
        PIEMessage message as an arg.
    """
    tert(callable(func), 'func must be Callable[[PIEMessage], None]')
    _functions['send_message'] = func


def signed_int_to_bytes(number: int) -> bytes:
    """Convert from arbitrarily large signed int to bytes."""
    tert(type(number) is int, 'number must be int')
    negative = number < 0
    number = abs(number)
    n_bits = floor(log2(number)) + 1 if number != 0 else 1
    n_bytes = ceil(n_bits/8)

    if negative:
        if n_bits % 8 == 0 and number > 2**(n_bytes*8-1):
            n_bytes += 1
        number = (1 << (n_bytes * 8 - 1)) + (2**(n_bytes * 8 - 1) - number)
    elif n_bits % 8 == 0:
        n_bytes += 1

    return number.to_bytes(n_bytes, 'big')

def int_to_2_bytes(number: int) -> bytes:
    """Convert from arbitrarily large signed int to bytes."""
    tert(type(number) is int, 'number must be int')
    negative = number < 0
    number = abs(number)
    n_bytes = 2

    if negative:
        number = (1 << (n_bytes * 8 - 1)) + (2**(n_bytes * 8 - 1) - number)

    return number.to_bytes(n_bytes, 'big')

def bytes_to_int(number: bytes) -> int:
    """Convert from bytes to a signed int."""
    tert(type(number) is bytes, 'number must be bytes')
    vert(len(number) > 0, 'number must not be empty')
    size = len(number) * 8
    number = int.from_bytes(number, 'big')
    negative = number >> (size - 1)

    return number - 2**size if negative else number


def encode_coordinates(coordinates: list[int]) -> bytes:
    """Encodes coordinates into a reasonably compact bytes format."""
    coords = [int_to_2_bytes(c) for c in coordinates]
    return b''.join(coords)

def decode_coordinates(encoded: bytes) -> list[int]:
    """Decodes coordinates from a reasonably compact bytes format."""
    tert(type(encoded) is bytes, 'encoded must be bytes of len%2=0')
    vert(len(encoded) % 2 == 0, 'encoded must be bytes of len%2=0')
    coords = []
    index = 0

    while index < len(encoded):
        coords.append(encoded[index:index+2])
        index += 2

    return [bytes_to_int(c) for c in coords]

def encode_big_coordinates(coordinates: list[int]) -> bytes:
    """Encodes coordinates into an adaptive bytes format."""
    coords = [signed_int_to_bytes(c) for c in coordinates]
    coords = [len(c).to_bytes(1, 'big') + c for c in coords]
    return b''.join(coords)

def decode_big_coordinates(encoded: bytes) -> list[int]:
    """Decodes coordinates from an adaptive bytes format."""
    coords = []
    index = 0

    while index < len(encoded):
        size = encoded[index]
        coords.append(encoded[index+1:index+1+size])
        index += 1 + size

    return [bytes_to_int(c) for c in coords]


class PIETree:
    id: bytes
    config: dict|CanJsonSerialize
    skey: bytes
    tree: LocalTree
    locality_level: int
    local_coords: list[int]
    child_coords: dict[bytes, list[int]]
    neighbor_coords: dict[bytes, list[int]]
    senders: list[CanUnicast]
    hooks: dict[str, Callable]

    def __init__(self, id: bytes = None,
                 config: dict|CanJsonSerialize = {},
                 skey: bytes = None,
                 tree: LocalTree = None,
                 locality_level: int = 0,
                 node_id: bytes = None,
                 local_coords: list[int] = None,
                 child_coords: dict[bytes, list[int]] = None,
                 neighbor_coords: dict[bytes, list[int]] = None) -> None:
        self.id = id if id else uuid4().bytes
        if config:
            if isinstance(config, CanJsonSerialize):
                self.id = sha256(config.to_json().encode()).digest()[:16]
            else:
                self.id = sha256(json.dumps(config).encode()).digest()[:16]
        self.skey = skey if skey else token_bytes(32)
        self.tree = tree if tree else LocalTree(id)
        self.locality_level = locality_level
        if node_id:
            self.tree.node_id = node_id
        self.local_coords = local_coords or []
        self.child_coords = child_coords or {}
        self.neighbor_coords = neighbor_coords or {}
        self.hooks = {}

    def set_hook(self, event: PIEEvent,
                 func: Callable[[PIEEvent, dict], dict]) -> None:
        """Sets a hook for an event. Takes the PIEEvent event and a
            Callable func as args. The func should take a PIEEvent event
            and a dict event data, and it should return the dict event
            data to be passed on to subsequent hooks; it may change the
            dict event data.
        """
        self.hooks[event.name] = func

    def add_hook(self, event: PIEEvent,
                 func: Callable[[PIEEvent, dict], dict]) -> None:
        """Adds a hook for an event. Takes the PIEEvent event and a
            Callable func as args. The func should take a PIEEvent event
            and a dict event data, and it should return the dict event
            data to be passed on to subsequent hooks; it may change the
            dict event data.
        """
        tert(type(event) is PIEEvent, 'event must be a PIEEvent')
        if event.name not in self.hooks:
            return self.set_hook(event, func)

        current_func = self.hooks[event.name]
        intermediate = lambda event, data: func(event, current_func(event, data))
        self.hooks[event.name] = intermediate

    def invoke_hook(self, event: PIEEvent, data: dict) -> None:
        """Invokes the hooks if present for the event, passing data."""
        tert(type(event) is PIEEvent, 'event must be PIEEvent')
        if event.name in self.hooks:
            self.hooks[event.name](event.name, {**data, 'tree': self})

    def add_sender(self, sender: CanUnicast) -> None:
        """Add a unicast sender."""
        tert(isinstance(sender, CanUnicast), 'sender must implement CanUnicast')
        if sender not in self.senders:
            self.senders.append(sender)

    def set_parent(self, parent_id: bytes, parent_coords: list[int],
                   index: str, weight: int = 1,
                   other_parent_data: dict = {}) -> None:
        """Sets the parent_id on the underlying tree. Sets local_coords
            based upon the parent_coords and the link weight.
        """
        parent_data = {**other_parent_data, 'parent_coords': parent_coords}
        self.invoke_hook(
            PIEEvent.BEFORE_SET_PARENT,
            {
                'parent_id': parent_id,
                'parent_data': parent_data,
                'current_parent_id': self.tree.parent_id,
                'current_parent_data': self.tree.parent_data
            }
        )

        local_coords = self.calculate_coords(parent_coords, index, weight)
        self.tree.set_parent(parent_id, parent_data)
        self.local_coords = local_coords

        self.invoke_hook(
            PIEEvent.AFTER_SET_PARENT,
            {
                'parent_id': parent_id,
                'parent_data': self.tree.parent_data
            }
        )

    def add_child(self, child_id: bytes,
                  child_data: dict|CanJsonSerialize = None,
                  link_weight: int = 1) -> None:
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
            PIEEvent.BEFORE_ADD_CHILD,
            {
                'child_id': child_id,
                'child_data': child_data,
                'child_ids': self.tree.child_ids,
                'all_child_data': self.tree.child_data
            }
        )

        self.tree.add_child(child_id, child_data)

        # set coordinates
        child_coords = self.calculate_coords(
            self.local_coords,
            self.child_index(child_id),
            link_weight
        )
        self.tree.child_data[child_id]['coords'] = child_coords
        self.child_coords[child_id] = child_coords

        self.invoke_hook(
            PIEEvent.AFTER_ADD_CHILD,
            {
                'child_id': child_id,
                'child_ids': self.tree.child_ids,
                'child_data': self.tree.child_data
            }
        )

    def remove_child(self, child_id: bytes) -> None:
        """Removes a child and calls any hooks for the
            BEFORE_REMOVE_CHILD and AFTER_REMOVE_CHILD events.
        """
        tert(type(child_id) is bytes, 'child_id must be bytes')
        vert(len(child_id) > 0, 'child_id must not be empty')

        child_data = self.tree.child_data[child_id] if child_id in self.tree.child_data else None

        self.invoke_hook(
            PIEEvent.BEFORE_REMOVE_CHILD,
            {
                'child_id': child_id,
                'child_ids': self.tree.child_ids,
                'child_data': child_data,
                'all_child_data': self.tree.child_data
            }
        )

        self.tree.remove_child(child_id=child_id)

        self.invoke_hook(
            PIEEvent.AFTER_REMOVE_CHILD,
            {
                'child_id': child_id,
                'child_ids': self.tree.child_ids,
                'child_data': child_data,
                'all_child_data': self.tree.child_data
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
            PIEEvent.BEFORE_ADD_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.tree.neighbor_ids,
                'all_neighbor_data': self.tree.neighbor_data
            }
        )

        self.tree.add_neighbor(neighbor_id, neighbor_data)
        if 'coords' in neighbor_data:
            self.neighbor_coords[neighbor_id] = neighbor_data['coords']

        self.invoke_hook(
            PIEEvent.AFTER_ADD_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.tree.neighbor_ids,
                'all_neighbor_data': self.tree.neighbor_data
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
            PIEEvent.BEFORE_REMOVE_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.tree.neighbor_ids,
                'all_neighbor_data': self.tree.neighbor_data
            }
        )

        self.tree.remove_neighbor(neighbor_id)

        self.invoke_hook(
            PIEEvent.AFTER_REMOVE_NEIGHBOR,
            {
                'neighbor_id': neighbor_id,
                'neighbor_data': neighbor_data,
                'neighbor_ids': self.tree.neighbor_ids,
                'all_neighbor_data': self.tree.neighbor_data
            }
        )

    def child_index(self, child_id: bytes) -> str:
        """Returns the str binary index of a child_id."""
        vert(child_id in self.tree.child_ids, 'child_id must be in child_ids')
        return bin(self.tree.child_ids.index(child_id)).split('b')[1]

    def process_message(self, message: PIEMessage) -> None:
        """Processes message. Executes any relevant hooks."""
        if message.treeid != self.id:
            return

        # receive message
        if message.dst == self.local_coords:
            return self.receive_message(message)

        # forward to nearest peer
        peers = []
        for cid, coords in self.child_coords.items():
            if coords == message.last_hop:
                continue
            peers.append((self.calculate_distance(coords, message.dst), coords, cid))
        for nid, coords in self.neighbor_coords.items():
            if coords == message.last_hop:
                continue
            peers.append((self.calculate_distance(coords, message.dst), coords, nid))

        peers.sort()

        bifurcation = None
        peer_coords = [p[1] for p in peers]
        for coords in message.bifurcations:
            if coords in peer_coords:
                bifurcation = peers[peer_coords.index(coords)]
                break

        next_hop = bifurcation if bifurcation else peers[0][1:]

        # invoke hook
        self.invoke_hook(
            PIEEvent.ROUTE_MESSAGE,
            {
                'message': message,
                'next_hop': next_hop
            }
        )

        self.send_message(message, next_hop[0], next_hop[1])

    def receive_message(self, message: PIEMessage) -> None:
        """Receive a message."""
        self.invoke_hook(PIEEvent.RECEIVE_MESSAGE, {'message': message})

    def send_message(self, message: PIEMessage, coords: list[int], peer_id: bytes) -> None:
        """Send a message to a specific peer."""
        self.invoke_hook(
            PIEEvent.SEND_MESSAGE,
            {
                'message': message,
                'coords': coords,
                'peer_id': peer_id
            }
        )

        for sender in self.senders:
            if sender.unicast(message, (peer_id, coords)):
                return

        raise UnicastException(peer_id)

    @staticmethod
    def calculate_distance(coords1: list[int], coords2: list[int]) -> int:
        """Calculates the distance between two sets of coordinates using
            the L-infinity norm.
        """
        max_coord_index = len(coords1) if len(coords1) < len(coords2) else len(coords2)
        return max([abs(coords1[i] - coords2[i]) for i in range(max_coord_index)])

    @staticmethod
    def calculate_coords(parent_coords: list[int], index: str,
                               link_weight: int = 1) -> list[int]:
        """Calculate the coordinates for a node using the parent coords
            and the str binary index.
        """
        tert(type(parent_coords) in (list, tuple),
             'parent_coords must be list of ints')
        tert(all(type(c) is int for c in parent_coords),
             'parent_coords must be list of ints')
        tert(type(index) is str, 'index must be str binary representaiton')
        tert(type(link_weight) is int, 'link_weight must be int >0')
        vert(link_weight > 0, 'link_weight must be int >0')
        new_coords = [
            (coord + link_weight) if coord > 0 else (coord - link_weight)
            for coord in parent_coords
        ]
        for bit in list(index):
            if bit == '0':
                new_coords.append(-link_weight)
            else:
                new_coords.append(link_weight)
        return new_coords

    def to_json(self) -> str:
        """Returns a json str encoding the instance data."""
        tree = b64encode(self.tree.to_json())
        return json.dumps({
            'id': self.id.hex(),
            'skey': self.skey.hex(),
            'tree': str(tree, 'utf-8'),
            'local_coords': self.local_coords,
            'child_coordinates': {
                cid.hex(): coords
                for cid, coords in self.child_coords.items()
            }
        })

    @classmethod
    def from_json(cls, data: str|bytes) -> PIETree:
        """Returns an instance with data deserialized from json."""
        unpacked = json.loads(data)
        child_coords = {
            bytes.fromhex(cid): coords
            for cid, coords in unpacked['child_coordinates']
        }
        return cls(
            id=bytes.fromhex(unpacked['id']),
            skey=bytes.fromhex(unpacked['skey']),
            tree=LocalTree.from_json(b64decode(unpacked['tree'])),
            local_coords=unpacked['local_coords'],
            child_coordinates=child_coords
        )
