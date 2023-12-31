from __future__ import annotations
from .errors import tert, vert, tressa, UnicastException
from .interfaces import CanJsonSerialize, CanUnicast, CanMulticast
from .spanningtree import LocalTree
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from enum import Enum, auto
from hashlib import sha256
from math import ceil, floor, log2
from secrets import token_bytes
from time import time
from typing import Callable
from uuid import uuid4
import json
import struct


class PIEEvent(Enum):
    """Events for hooks on the PIETree."""
    RECEIVE_MESSAGE = auto()
    DELIVER_PACKET = auto()
    CRYPTO_ERROR = auto()
    RECEIVE_PEER_INFO = auto()
    RECEIVE_ACK = auto()
    RECEIVE_PING = auto()
    RECEIVE_ECHO = auto()
    RECEIVE_TRACE_ROUTE = auto()
    RECEIVE_TRACE_ROUTE_ECHO = auto()
    RECEIVE_SET_ROOT = auto()
    RECEIVE_OFFER_ASSIGNMENT = auto()
    RECEIVE_REQUEST_ASSIGNMENT = auto()
    RECEIVE_ACCEPT_ASSIGNMENT = auto()
    RECEIVE_ANNOUNCE_ASSIGNMENT = auto()
    RECEIVE_RELEASE_ASSIGNMENT = auto()
    RECEIVE_ERROR = auto()
    RECEIVE_UNREACHABLE_ERROR = auto()
    SET_ROOT = auto()
    SEND_MESSAGE = auto()
    MULTICAST_MESSAGE = auto()
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
    """Valid message types."""
    DEFAULT = 0
    HELLO = 1
    PING = 2
    ECHO = 3
    TRACE_ROUTE = 4
    TRACE_ROUTE_ECHO = 5
    SET_ROOT = 6
    OFFER_ASSIGNMENT = 7
    REQUEST_ASSIGNMENT = 8
    ACCEPT_ASSIGNMENT = 9
    ANNOUNCE_ASSIGNMENT = 10
    RELEASE_ASSIGNMENT = 11
    ACKNOWLEDGE_MESSAGE = 12
    AUTH_ERROR = 13
    UNREACHABLE_ERROR = 14


@dataclass
class PIEMessage:
    msg_type: PIEMsgType
    treeid: bytes
    dst: list[int]
    dst_id: bytes
    src: list[int]
    src_id: bytes
    body: bytes
    bifurcations: list[list[int]] = field(default_factory=list)
    ttl: int = field(default=255)
    flow_label: bytes = field(default_factory=lambda: token_bytes(4))
    seq: int = field(default=0)
    last_hop: list[int] = field(default=None)

    def encode_header(self, use_big_coords: bool = False,
                      use_small_coords: bool = False) -> bytes:
        """Serialize header information to bytes."""
        if use_big_coords:
            src = encode_big_coordinates(self.src)
            dst = encode_big_coordinates(self.dst)
            bifurcations = [encode_big_coordinates(b) for b in self.bifurcations]
        elif use_small_coords:
            src = encode_small_coordinates(self.src)
            dst = encode_small_coordinates(self.dst)
            bifurcations = [encode_small_coordinates(b) for b in self.bifurcations]
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
            f'!BBB4sB{len(self.treeid)}sB{len(dst)}sB{len(self.dst_id)}sB' +
            f'{len(src)}sB{len(self.src_id)}s{len(bifurcations)}s',
            self.msg_type.value,
            len(self.treeid),
            self.ttl,
            self.flow_label,
            self.seq,
            self.treeid,
            len(dst),
            dst,
            len(self.dst_id),
            self.dst_id,
            len(src),
            src,
            len(self.src_id),
            self.src_id,
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
        msg_type, treeid_len, ttl, flow_label, seq, header = struct.unpack(
            f'!BBB4sB{len(header)-8}s',
            header
        )
        treeid, dst_len, header = struct.unpack(
            f'!{treeid_len}sB{len(header)-1-treeid_len}s',
            header
        )
        dst, dst_id_len, header = struct.unpack(
            f'!{dst_len}sB{len(header)-1-dst_len}s',
            header
        )
        dst_id, src_len, header = struct.unpack(
            f'!{dst_id_len}sB{len(header)-1-dst_id_len}s',
            header
        )
        src, src_id_len, header = struct.unpack(
            f'!{src_len}sB{len(header)-1-src_len}s',
            header
        )
        src_id, bifurcations = struct.unpack(
            f'!{src_id_len}s{len(header)-src_id_len}s',
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
            dst_id,
            src,
            src_id,
            bifurcations,
            ttl,
            flow_label,
            seq
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
        msg_type, treeid, dst, dst_id, src, src_id, bifurcations, ttl, \
            flow_label, seq = cls.decode_header(header, use_big_coords)
        return cls(msg_type, treeid, dst, dst_id, src, src_id, body,
                   bifurcations=bifurcations, ttl=ttl, flow_label=flow_label,
                   seq=seq)

    def header_id(self, use_big_coords: bool = False) -> bytes:
        """Returns a unique ID for the message header excluding ttl."""
        if use_big_coords:
            src = encode_big_coordinates(self.src)
            dst = encode_big_coordinates(self.dst)
        else:
            src = encode_coordinates(self.src)
            dst = encode_coordinates(self.dst)

        header = struct.pack(
            f'!BB4sB{len(self.treeid)}sB{len(dst)}sB{len(self.dst_id)}sB' +
            f'{len(src)}sB{len(self.src_id)}s',
            self.msg_type.value,
            len(self.treeid),
            self.flow_label,
            self.seq,
            self.treeid,
            len(dst),
            dst,
            len(self.dst_id),
            self.dst_id,
            len(src),
            src,
            len(self.src_id),
            self.src_id
        )

        return sha256(header).digest()[:16]

    def body_id(self) -> bytes:
        """Returns a unique ID for the message body."""
        return sha256(self.body).digest()[:16]

    def msg_id(self, use_big_coords: bool = False) -> bytes:
        """Returns a unique ID for the message."""
        return sha256(self.header_id(use_big_coords) + self.body_id()).digest()[:16]


@dataclass
class PIEMsgBody:
    body: bytes
    sig: bytes = field(default=b'')

    def sign(self, skey: bytes) -> None:
        """Sign the message with the skey and _functions['sign'] func."""
        if _functions['sign']:
            self.sig = _functions['sign'](skey, self.body)

    def check_sig(self, vkey: bytes) -> bool | None:
        """Checks if the signature is valid."""
        if self.sig and _functions['check_sig']:
            return _functions['check_sig'](vkey, self.body, self.sig)

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return struct.pack(
            f'!BB{len(self.sig)}s{len(self.body)}s',
            len(self.sig),
            len(self.body),
            self.sig,
            self.body,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PIEMsgBody:
        "Deserialize from bytes."
        sig_len, body_len, data = struct.unpack(f'!BB{len(data)-2}s', data)
        sig, body = struct.unpack(f'{sig_len}s{body_len}s', data)
        return PIEMsgBody(body, sig)


_functions = {
    'sign': None,
    'check_sig': None,
    'elect_root': None,
    'make_auth': None,
    'check_auth': None,
}


def set_sign_function(func: Callable[[bytes, bytes], bytes]) -> None:
    """Sets a function for signing messages. Function must take the
        private key bytes and message bytes as arguments and return the
        signature bytes.
    """
    tert(callable(func), 'func must be Callable[[bytes, bytes], bytes]')
    _functions['sign'] = func


def set_check_sig_function(func: Callable[[bytes, bytes, bytes], bool]) -> None:
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


def set_make_auth_func(func: Callable[[bytes, bytes, bytes], bytes]) -> None:
    """Sets a function for making auth data. Function must take the
        bytes auth config, bytes node ID, and bytes skey as args and
        return bytes auth data.
    """
    tert(callable(func), 'func must be Callable[[bytes, bytes, bytes], bytes]')
    _functions['make_auth'] = func


def set_check_auth_func(func: Callable[[bytes, bytes, bytes], bool]) -> None:
    """Sets a function for checking auth data. Function must take the
        bytes auth root, bytes node ID, and bytes auth data as args and
        return True if the auth data is valid and False otherwise.
    """
    tert(callable(func), 'func must be Callable[[bytes, bytes, bytes], bool]')
    _functions['check_auth'] = func


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

def unsigned_int_to_bytes(number: int) -> bytes:
    """Convert from arbitrarily large unsigned int to bytes."""
    tert(type(number) is int, 'number must be int')
    n_bits = floor(log2(number)) + 1 if number != 0 else 1
    n_bytes = ceil(n_bits/8)

    return number.to_bytes(n_bytes, 'big')

def int_to_1_byte(number: int) -> bytes:
    """Convert from signed int in [-128, 127] to bytes."""
    tert(type(number) is int, 'number must be int')
    negative = number < 0
    number = abs(number)
    n_bytes = 1

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


def _pack_coord_group(coords: list[int]) -> bytes:
    """Packs a coord group into 2 bytes per 7 coords."""
    tert(type(coords) is list, 'coords must be list[int]')
    tert(all(type(c) is int for c in coords), 'coords must be list[int]')
    magnitude = abs(coords[0])
    signs = '1'
    size = len(coords) if len(coords) < 7 else 7
    for i in range(size):
        signs += '0' if coords[i] > 0 else '1'

    first_7 = int(signs, 2).to_bytes(1, 'big') + magnitude.to_bytes(1, 'big')

    if len(coords) > 7:
        return first_7 + _pack_coord_group(magnitude, coords[7:])
    return first_7

def _unpack_coord_group(group: bytes) -> list[int]:
    """Unpacks a coord gorup from 2 bytes into list of signed ints."""
    tert(type(group) is bytes, 'group must be 2 bytes')
    vert(len(group) == 2, 'group must be 2 bytes')
    signs = bin(group[0]).split('b')[1]
    magnitude = group[1]
    size = len(signs) - 1
    signs = signs[1:]
    coords = []

    for i in range(size):
        coords.append(magnitude if signs[i] == '0' else -magnitude)

    return coords

def encode_coordinates(coordinates: list[int]) -> bytes:
    """Encodes coordinates into a compact bytes format. Max magnitude is
        255, and every 7 coordinates with the same magnitude are encoded
        into 2 bytes maintaining the magnitude and sign of each
        coordinate.
    """
    # first group by magnitude
    coord_groups = {}
    for c in coordinates:
        if abs(c) not in coord_groups:
            coord_groups[abs(c)] = []
        coord_groups[abs(c)].append(c)

    # encode signs by grouping up to 7 of the same magnitude
    coords = []
    for magnitude in coord_groups:
        coords.append(_pack_coord_group(coord_groups[magnitude]))
    return b''.join(coords)

def decode_coordinates(encoded: bytes) -> list[int]:
    """Decodes coordinates from a compact bytes format. Max mangitude is
        255, and every 2 bytes encode up to 7 coordinates sharing a
        magnitude, with the first byte encoding the number of coords and
        the signs of each.
    """
    tert(type(encoded) is bytes, 'encoded must be bytes of len%2=0')
    vert(len(encoded) % 2 == 0, 'encoded must be bytes of len%2=0')
    coords = []
    index = 0

    while index < len(encoded):
        coords.extend(_unpack_coord_group(encoded[index:index+2]))
        index += 2

    return coords

def encode_small_coordinates(coordinates: list[int]) -> bytes:
    """Encodes coordinates into a compact bytes format with max
        magnitude of 127.
    """
    coords = [int_to_1_byte(c) for c in coordinates]
    return b''.join(coords)

def decode_small_coordinates(encoded: bytes) -> list[int]:
    """Decodes coordinates from compact bytes format with max magnitude
        of 127.
    """
    tert(type(encoded) is bytes, 'encoded must be bytes')
    coords = []
    index = 0

    while index < len(encoded):
        coords.append(encoded[index:index+1])
        index += 1

    return [bytes_to_int(c) for c in coords]

def _pack_big_coord_group(coords: list[int]) -> bytes:
    """Packs a coord group into 7 coords."""
    tert(type(coords) is list, 'coords must be list[int]')
    tert(all(type(c) is int for c in coords), 'coords must be list[int]')
    magnitude = abs(coords[0])
    magnitude = unsigned_int_to_bytes(magnitude)
    mag_size = len(magnitude).to_bytes(1, 'big')
    signs = '1'
    size = len(coords) if len(coords) < 7 else 7
    for i in range(size):
        signs += '0' if coords[i] > 0 else '1'

    first_7 = int(signs, 2).to_bytes(1, 'big') + mag_size + magnitude

    if len(coords) > 7:
        return first_7 + _pack_big_coord_group(coords[7:])
    return first_7

def _unpack_big_coord_group(group: bytes) -> tuple[list[int], int]:
    """Unpacks a coord gorup from N>2 bytes into list of signed ints."""
    tert(type(group) is bytes, 'group must be bytes with len>2')
    vert(len(group) > 2, 'group must be bytes with len>2')
    signs = bin(group[0]).split('b')[1]
    mag_size = group[1]
    magnitude = int.from_bytes(group[2:mag_size+2], 'big')
    size = len(signs) - 1
    signs = signs[1:]
    coords = []

    for i in range(size):
        coords.append(magnitude if signs[i] == '0' else -magnitude)

    return (coords, mag_size+2)

def encode_big_coordinates(coordinates: list[int]) -> bytes:
    """Encodes coordinates into a compact, adaptive bytes format without
        maximum magnitude. Every 7 coordinates sharing a magnitude are
        encoded into 2 bytes maintaining the magnitude and sign of each
        coordinate.
    """
    # first group by magnitude
    coord_groups = {}
    for c in coordinates:
        if abs(c) not in coord_groups:
            coord_groups[abs(c)] = []
        coord_groups[abs(c)].append(c)

    # encode signs by grouping up to 7 of the same magnitude
    coords = []
    for magnitude in coord_groups:
        coords.append(_pack_big_coord_group(coord_groups[magnitude]))
    return b''.join(coords)

def decode_big_coordinates(encoded: bytes) -> list[int]:
    """Decodes coordinates into a compact, adaptive bytes format without
        maximum magnitude. Every 7 coordinates sharing a magnitude are
        encoded into 2 bytes maintaining the magnitude and sign of each
        coordinate.
    """
    tert(type(encoded) is bytes, 'encoded must be bytes')
    coords = []
    index = 0

    while index < len(encoded):
        unpacked, advance = _unpack_big_coord_group(encoded[index:])
        coords.extend(unpacked)
        index += advance

    return coords


@dataclass
class SrcAidedRouteTable:
    """Route table for storing bifurcations detected during trace routes
        initiated by the local node. Does not store bifurcations for
    """
    bifurcations: dict[tuple[bytes, bytes], tuple[int, list[list[int]]]] = field(default_factory=dict)
    encode_coords: Callable[[list[int]], bytes] = field(default=encode_coordinates)

    def set_bifurcations(self, tree_id: bytes, dst: list[int], bifurcations: list[list[int]]) -> None:
        """Set bifurcations for a destination on a tree."""
        tert(type(tree_id) is bytes, 'tree_id must be bytes')
        tert(type(dst) is list, 'dst must be list of ints')
        tert(all(type(coord) is int for coord in dst), 'dst must be list of ints')
        tert(type(bifurcations) is list, 'bifurcations must be list[list[int]]')
        self.bifurcations[(tree_id.hex(), self.encode_coords(dst))] = bifurcations

    def get_bifurcations(self, tree_id: bytes, dst: list[int] | bytes) -> list[list[int]]:
        """Get the bifurcations for a destination on a tree."""
        tert(type(tree_id) is bytes, 'tree_id must be bytes')
        tert(type(dst) in (list, bytes),
             'dst must be list of ints or bytes encoding')
        if type(dst) is list:
            tert(all(type(coord) is int for coord in dst),
                 'dst must be list of ints or bytes encoding')
        if (tree_id.hex(), self.encode_coords(dst)) in self.bifurcations:
            return self.bifurcations[(tree_id.hex(), self.encode_coords(dst))]
        return []

    def add_bifurcation(self, tree_id: bytes, dst: list[int], bifurcation: list[int]) -> None:
        """Adds a bifurcation."""
        bifs = self.get_bifurcations(tree_id, dst)
        if bifurcation not in bifs:
            bifs.append(bifurcation)
        self.set_bifurcations(tree_id, dst, bifs)

    def to_json(self) -> str:
        """Return instance data serialized to json."""
        return json.dumps(self.bifurcations)

    @classmethod
    def from_json(cls, data: str) -> SrcAidedRouteTable:
        """Deserialize data from json and return instance."""
        return cls(json.loads(data))


class PIETree:
    id: bytes
    config: dict
    root: bytes
    skey: bytes
    tree: LocalTree
    locality_level: int
    local_coords: list[int]
    assignment_cert: bytes
    child_coords: dict[bytes, list[int]]
    neighbor_coords: dict[bytes, list[int]]
    senders: list[CanUnicast | CanMulticast]
    hooks: dict[str, Callable]
    route_table: SrcAidedRouteTable

    def __init__(self, id: bytes = None,
                 config: dict|CanJsonSerialize = {},
                 root: bytes = b'',
                 skey: bytes = None,
                 tree: LocalTree = None,
                 locality_level: int = 0,
                 node_id: bytes = None,
                 local_coords: list[int] = None,
                 assignment_cert: bytes = None,
                 child_coords: dict[bytes, list[int]] = None,
                 neighbor_coords: dict[bytes, list[int]] = None,
                 route_table: SrcAidedRouteTable = None) -> None:
        self.id = id if id else uuid4().bytes
        self.root = root
        if config:
            self.id = sha256(json.dumps(config).encode('utf-8')).digest()[:16]
            self.root = self.root or (config['init_root'] if 'init_root' in config else None)
            self.config = config
        else:
            self.config = {}
        self.skey = skey if skey else token_bytes(32)
        self.tree = tree if tree else LocalTree(id)
        self.locality_level = locality_level
        if node_id:
            self.tree.node_id = node_id
        self.local_coords = local_coords or []
        self.assignment_cert = assignment_cert or b''
        self.child_coords = child_coords or {}
        self.neighbor_coords = neighbor_coords or {}
        self.senders = []
        self.hooks = {}
        if route_table:
            self.route_table = route_table
        else:
            self.route_table = SrcAidedRouteTable(
                encode_coords=lambda coords: self._encode_coords(coords)
            )

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
            self.hooks[event.name](event, {**data, 'tree': self})

    def add_sender(self, sender: CanUnicast) -> None:
        """Add a unicast sender."""
        tert(isinstance(sender, CanUnicast), 'sender must implement CanUnicast')
        if sender not in self.senders:
            self.senders.append(sender)

    def set_parent(self, parent_id: bytes, parent_coords: list[int],
                   index: str, weight: int = 1,
                   other_parent_data: dict = {}) -> None:
        """Sets the parent_id on the underlying tree. Sets local_coords
            based upon the parent_coords and the link weight. Raises
            ValueError if must_use_cert set in config but cert missing
            from parent_data.
        """
        if 'cert' not in other_parent_data and 'use_certs' in self.config:
            raise ValueError('missing required cert')
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

        if 'cert' in parent_data:
            body = PIEMsgBody(json.dumps({
                'parent_id': parent_id.hex(),
                'cert': parent_data['cert'],
                'coords': local_coords,
            }).encode('utf-8'))
            self.assignment_cert = b64decode(parent_data['cert'])
        else:
            body = PIEMsgBody(json.dumps({
                'parent_id': parent_id.hex(),
                'coords': local_coords
            }).encode('utf-8'))
        body.sign(self.skey)

        # send ACCEPT_ASSIGNMENT message to new parent
        self._accept_assignment(parent_id, parent_coords, body)

        # send ANNOUNCE_ASSIGNMENT to neighbors
        self._announce_assignment(body)

        # send OFFER_ASSIGNMENT to children
        self._offer_assignments(parent_data)

        self.invoke_hook(
            PIEEvent.AFTER_SET_PARENT,
            {
                'parent_id': parent_id,
                'parent_data': self.tree.parent_data
            }
        )

    def _accept_assignment(self, parent_id: bytes, parent_coords: list[int],
                           body: PIEMsgBody) -> None:
        """Send ACCEPT_ASSIGNMENT to new parent."""
        self.send_message(PIEMessage(
            PIEMsgType.ACCEPT_ASSIGNMENT,
            self.id,
            parent_coords,
            parent_id,
            self.local_coords,
            self.tree.node_id,
            body.to_bytes(),
        ), parent_id, parent_coords)

    def _announce_assignment(self, body: PIEMsgBody) -> None:
        """Send ANNOUNCE_ASSIGNMENT to neighbors"""
        for nid in self.tree.neighbor_ids:
            if nid not in self.neighbor_coords:
                continue
            self.send_message(PIEMessage(
                PIEMsgType.ANNOUNCE_ASSIGNMENT,
                self.id,
                self.neighbor_coords[nid],
                nid,
                self.local_coords,
                self.tree.node_id,
                body.to_bytes(),
            ), nid, self.neighbor_coords[nid] if nid in self.neighbor_coords else [])

    def _offer_assignments(self, parent_data: dict) -> None:
        """Send OFFER_ASSIGNMENT to children and turn them into neighbors."""
        child_ids = [*self.tree.child_ids]
        for cid in child_ids:
            try:
                msg = self._make_offer_assignment_msg(
                    cid, self.child_coords[cid], parent_data
                )
                self.send_message(msg, cid)
                self.add_neighbor(cid, self.tree.child_data[cid])
            except UnicastException:
                ...
            finally:
                self.remove_child(cid)

    def _make_offer_assignment_msg(self, peer_id: bytes, peer_coords: list[int],
                                   parent_data: dict = {}) -> PIEMessage:
        """Create a PIEMessage that offers assignment to a peer."""
        child_index = self.child_index(peer_id)
        child_coords = self.calculate_coords(self.local_coords, child_index)

        if 'use_certs' in self.config:
            cert_data = {
                'parent_id': b64encode(self.tree.node_id).decode('utf-8'),
                'parent_coords': self.local_coords,
                'coords': child_coords,
                'index': child_index,
                'root': b64encode(self.root).decode('utf-8')
            }
            if 'cert' in parent_data:
                child_cert = self.make_cert(cert_data, base_cert=b64decode(parent_data['cert']))
            else:
                child_cert = self.make_cert(cert_data)
            body = PIEMsgBody(child_cert)
        else:
            body = PIEMsgBody(json.dumps({
                'parent_id': b64encode(self.tree.node_id).decode('utf-8'),
                'parent_coords': self.local_coords,
                'coords': child_coords,
                'index': child_index,
                'root': b64encode(self.root).decode('utf-8')
            }).encode('utf-8'))
        body.sign(self.skey)
        return PIEMessage(
            PIEMsgType.OFFER_ASSIGNMENT,
            self.id,
            peer_coords,
            peer_id,
            self.local_coords,
            self.tree.node_id,
            body.to_bytes(),
            ttl=1
        )

    def make_cert(self, cert_data: dict, base_cert: bytes = b'') -> bytes:
        """Makes a signed certificate."""
        tert(callable(_functions['sign']), 'missing callable sign function')
        cert = {**cert_data, 'parent_id': b64encode(self.tree.node_id).decode('utf-8')}
        if base_cert:
            cert['base'] = b64encode(base_cert).decode('utf-8')
        cert = b64encode(json.dumps(cert).encode('utf-8'))
        sig = _functions['sign'](cert, self.skey)
        return json.dumps({
            'cert': cert,
            'sig': b64encode(sig).decode('utf-8')
        }).encode('utf-8')

    def check_cert(self, cert: bytes) -> bool:
        """Checks a certificate, traversing the parents to the root.
            Returns True if all certs have the right structure, all
            signatures verify, and the root is valid. Returns False
            otherwise.
        """
        tert(callable(_functions['check_sig']), 'missing callable check_sig function')
        try:
            cert = json.loads(cert.decode('utf-8'))
            body = cert['data'].encode('utf-8')
            sig = b64decode(cert['sig'])
            data = json.loads(b64decode(cert['body']).decode('utf-8'))
            parent_id = b64decode(data['parent_id'])
            # first check the signature
            if not _functions['check_sig'](parent_id, body, sig):
                return False
            # if there is a base cert, check it
            if 'base' in data:
                return self.check_cert(b64decode(data['base']))
            # otherwise make sure it was signed by the root
            if parent_id != self.root:
                return self.try_elect_root(parent_id)
        except BaseException:
            return False
        return True

    def add_child(self, child_id: bytes,
                  child_data: dict = {},
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
        if self.tree.child_data[child_id]:
            self.tree.child_data[child_id]['coords'] = child_coords
        else:
            self.tree.child_data[child_id] = {'coords': child_coords}
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
                     neighbor_data: dict) -> None:
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

        self.route_message(message)

    def route_message(self, message: PIEMessage) -> None:
        """Finds the next hop and sends to that peer."""
        next_hop = self.calculate_next_hop(message)

        # invoke hook
        self.invoke_hook(
            PIEEvent.ROUTE_MESSAGE,
            {
                'message': message,
                'next_hop': next_hop
            }
        )

        if message.msg_type == PIEMsgType.TRACE_ROUTE:
            self.respond_to_trace_route(message)

        message.ttl -= 1
        self.send_message(message, next_hop[0], next_hop[1])

    def calculate_next_hop(self, message: PIEMessage) -> tuple[bytes, list[int]]:
        """Chooses the next hop based on the distance metric and
            bifurcations added to the header.
        """
        if message.dst_id in self.tree.child_ids or message.dst_id in self.tree.neighbor_ids:
            return (message.dst, message.dst_id)

        # forward to nearest peer
        peers = []
        for cid, coords in self.child_coords.items():
            if coords == message.last_hop:
                continue
            peers.append((self.calculate_distance(coords, message.dst), cid, coords))
        for nid, coords in self.neighbor_coords.items():
            if coords == message.last_hop:
                continue
            peers.append((self.calculate_distance(coords, message.dst), nid, coords))

        peers.sort()

        bifurcation = None
        peer_coords = [p[2] for p in peers]
        for coords in message.bifurcations:
            if coords in peer_coords and coords != message.last_hop:
                bifurcation = peers[peer_coords.index(coords)][1:]
                break

        next_hop = bifurcation if bifurcation else peers[0][1:]
        return next_hop

    def try_elect_root(self, new_root: bytes) -> bool:
        """Tries to elect a new root. Returns True if successful and
            False otherwise.
        """
        if _functions['elect_root']:
            if _functions['elect_root'](self.root, new_root, self.locality_level):
                self.invoke_hook(
                    PIEEvent.SET_ROOT,
                    {
                        'old_root': self.root,
                        'new_root': new_root
                    }
                )
                self.root = new_root
                return True
        return False

    def _encode_coords(self, coords: list[int]) -> bytes:
        """Encode the coords using the correct format."""
        if 'use_big_coords' in self.config:
            return encode_big_coordinates(coords)
        elif 'use_small_coords' in self.config:
            return encode_small_coordinates(coords)
        else:
            return encode_coordinates(coords)

    def _decode_coords(self, coords: bytes) -> list[int]:
        """Decode the coords using the correct format."""
        if 'use_big_coords' in self.config:
            return decode_big_coordinates(coords)
        elif 'use_small_coords' in self.config:
            return decode_small_coordinates(coords)
        else:
            return decode_coordinates(coords)

    def receive_message(self, message: PIEMessage) -> None:
        """Receive a message."""
        msgbody = PIEMsgBody.from_bytes(message.body)
        self.invoke_hook(PIEEvent.RECEIVE_MESSAGE, {
            'message': message,
            'msgbody': msgbody,
        })

        if msgbody.sig and _functions['check_sig']:
            if not _functions['check_sig'](message.src_id, msgbody.body, msgbody.sig):
                return self.invoke_hook(
                    PIEEvent.CRYPTO_ERROR,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )

        peer_info = json.loads(str(msgbody.body, 'utf-8'))
        peer_id = bytes.fromhex(peer_info['id'])
        peer_info['id'] = peer_id

        # send ACK except when receiving ACK
        if message.msg_type is not PIEMsgType.ACKNOWLEDGE_MESSAGE:
            rsp_body = PIEMsgBody(message.body_id())
            rsp_body.sign(self.skey)
            try:
                self.route_message(PIEMessage(
                    PIEMsgType.ACKNOWLEDGE_MESSAGE,
                    self.id,
                    message.src,
                    peer_id,
                    self.local_coords,
                    self.tree.node_id,
                    rsp_body.to_bytes(),
                    bifurcations=self.route_table.get_bifurcations(self.id, message.src)
                ))
            except:
                ...

        # handle protocol events
        match message.msg_type:
            case PIEMsgType.DEFAULT:
                # this was the destination
                self.invoke_hook(
                    PIEEvent.DELIVER_PACKET,
                    {
                        'message': message
                    }
                )
            case PIEMsgType.HELLO:
                # peer information
                self.invoke_hook(
                    PIEEvent.RECEIVE_PEER_INFO,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_hello(message, peer_id, peer_info)
            case PIEMsgType.PING:
                self.invoke_hook(
                    PIEEvent.RECEIVE_PING,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_ping(message)
            case PIEMsgType.ECHO:
                self.invoke_hook(
                    PIEEvent.RECEIVE_ECHO,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
            case PIEMsgType.TRACE_ROUTE:
                self.invoke_hook(
                    PIEEvent.RECEIVE_TRACE_ROUTE,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_trace_route(message)
            case PIEMsgType.TRACE_ROUTE_ECHO:
                self.invoke_hook(
                    PIEEvent.RECEIVE_TRACE_ROUTE_ECHO,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_tracert_echo(message, msgbody)
            case PIEMsgType.SET_ROOT:
                self.invoke_hook(
                    PIEEvent.RECEIVE_SET_ROOT,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self.try_elect_root(message, msgbody)
            case PIEMsgType.OFFER_ASSIGNMENT:
                self.invoke_hook(
                    PIEEvent.RECEIVE_OFFER_ASSIGNMENT,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_offer_assignment(message, msgbody)
            case PIEMsgType.REQUEST_ASSIGNMENT:
                self.invoke_hook(
                    PIEEvent.RECEIVE_REQUEST_ASSIGNMENT,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_request_assignment(message, msgbody)
            case PIEMsgType.ACCEPT_ASSIGNMENT:
                self.invoke_hook(
                    PIEEvent.RECEIVE_ACCEPT_ASSIGNMENT,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_accept_assignment(message, msgbody)
            case PIEMsgType.ANNOUNCE_ASSIGNMENT:
                self.invoke_hook(
                    PIEEvent.RECEIVE_ANNOUNCE_ASSIGNMENT,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_announce_assignment(message, msgbody)
            case PIEMsgType.RELEASE_ASSIGNMENT:
                self.invoke_hook(
                    PIEEvent.RECEIVE_RELEASE_ASSIGNMENT,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
                self._handle_release_assignment(message, msgbody)
            case PIEMsgType.ACKNOWLEDGE_MESSAGE:
                self.invoke_hook(
                    PIEEvent.RECEIVE_ACK,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
            case PIEMsgType.AUTH_ERROR:
                self.invoke_hook(
                    PIEEvent.RECEIVE_ERROR,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )
            case PIEMsgType.UNREACHABLE_ERROR:
                self.invoke_hook(
                    PIEEvent.RECEIVE_UNREACHABLE_ERROR,
                    {
                        'message': message,
                        'msgbody': msgbody
                    }
                )

    def make_hello(self, dst_id: bytes = b'', dst: list[int] = []) -> None:
        """Make a a message for HELLO type messages to introduce a node
            to peers.
        """
        data = {
            'id': self.tree.node_id.hex(),
            'coords': self.local_coords
        }
        if 'auth_base' in self.config and _functions['make_auth']:
            data['auth'] = _functions['make_auth'](
                b64decode(self.config['auth_base']),
                self.tree.node_id,
                self.skey
            )
            data['auth'] = b64encode(data['auth']).decode('utf-8')
        msgbody = PIEMsgBody(json.dumps(data).encode('utf-8'))
        msgbody.sign(self.skey)
        return PIEMessage(
            PIEMsgType.HELLO,
            self.id,
            dst,
            dst_id,
            self.local_coords,
            self.tree.node_id,
            msgbody.to_bytes(),
            ttl=1
        )

    def send_hello(self, dst_id: bytes = b'', dst: list[int] = []) -> None:
        self.send_message(self.make_hello(dst_id, dst), dst_id, dst)

    def _handle_hello(self, message: PIEMessage, peer_id: bytes,
                      peer_info: dict) -> None:
        """Handle incoming peer information."""
        if peer_id not in self.tree.child_ids and \
            peer_id not in self.tree.neighbor_ids:
            if 'auth' not in peer_info:
                return
            try:
                if 'auth_base' in self.config and _functions['check_auth']:
                    has_valid_auth = _functions['check_auth'](
                        b64decode(self.config['auth_base']),
                        peer_id,
                        b64decode(peer_info['auth'])
                    )
                    if not has_valid_auth:
                        return
                # respond with HELLO to new peer
                self.send_message(self.make_hello(peer_id, message.dst), peer_id)
                self.add_neighbor(peer_id, peer_info)
            except UnicastException:
                ...
        else:
            # update a current neighbor
            self.add_neighbor(peer_id, peer_info)

    def _handle_ping(self, message: PIEMessage) -> None:
        """Responds to ping."""
        rsp_body = PIEMsgBody(message.body_id())
        rsp_body.sign(self.skey)
        seq = message.seq + 255 - message.ttl
        seq = seq if seq < 256 else 255
        self.route_message(PIEMessage(
            PIEMsgType.ECHO,
            self.id,
            message.src,
            message.src_id,
            self.local_coords,
            self.tree.node_id,
            rsp_body.to_bytes(),
            bifurcations=self.route_table.get_bifurcations(self.id, message.src),
            flow_label=message.flow_label,
            seq=seq
        ))

    def _handle_trace_route(self, message: PIEMessage) -> None:
        """Responds to a TRACE_ROUTE message."""
        # first see if there is a path bifurcation
        bifurcation = b''
        reverse_msg = PIEMessage(PIEMsgType.DEFAULT, self.id,
                                    message.src, message.src_id,
                                    message.dst, message.dst_id, b'',
                                    flow_label=message.flow_label)
        last_hop = self.calculate_next_hop(reverse_msg)
        if message.last_hop:
            if last_hop[1] != message.last_hop:
                bifurcation = last_hop[1]

        # then send a TRACE_ROUTE_ECHO to src
        if bifurcation:
            bifurcation = self._encode_coords(bifurcation)
        body = PIEMsgBody(bifurcation)
        body.sign(self.skey)
        seq = message.seq + 255 - message.ttl
        seq = seq if seq < 256 else 255
        reverse_msg = PIEMessage(PIEMsgType.TRACE_ROUTE_ECHO, self.id,
                                    message.src, message.src_id,
                                    self.local_coords, self.tree.node_id,
                                    body.to_bytes(), seq=seq,
                                    flow_label=message.flow_label)
        self.send_message(reverse_msg, last_hop[0], last_hop[1])

    def _handle_tracert_echo(self, message: PIEMessage, msgbody: PIEMsgBody) -> None:
        """Adds any bifurcation noticed."""
        if msgbody.body:
            if 'use_big_coords' in self.config:
                bif = decode_big_coordinates(msgbody.body)
            elif 'use_small_coords' in self.config:
                bif = decode_small_coordinates(msgbody.body)
            else:
                bif = decode_coordinates(msgbody.body)
            self.route_table.add_bifurcation(
                self.id,
                message.dst,
                bif
            )

    def _handle_offer_assignment(self, message: PIEMessage, msgbody: PIEMsgBody) -> None:
        """Handle an assignment offer. Raises UsageError if check_sig
            function is missingk, TypeError if an argument is of the
            wrong type, and ValueError if an arg is malformed.
        """
        tert(isinstance(message, PIEMessage), 'message must be PIEMessage')
        tert(isinstance(msgbody, PIEMsgBody), 'message must be PIEMsgBody')
        data = json.loads(msgbody.body.decode('utf-8'))
        if 'auth_base' in self.config:
            if not _functions['check_auth']:
                return
            if not _functions['check_auth'](
                b64decode(self.config['auth_base']),
                message.src_id,
                b64decode(data['auth'])
            ):
                self.send_error_message(message.src, message.src_id,
                                        PIEMsgType.AUTH_ERROR, b'invalid auth')
                return
        if 'use_certs' in self.config:
            tressa(callable(_functions['check_sig']), 'missing callable check_sig function')
            vert('cert' in data, 'missing cert data')
            vert('sig' in data, 'missing sig data')
            cert = data['cert']
            if self.check_cert(b64decode(cert)):
                cert_data = json.loads(b64decode(cert))
                parent_id = b64decode(cert_data['parent_id'])
                parent_data = {'cert': cert, 'coords': cert_data['coords']}
                self.set_parent(parent_id, cert_data['coords'], cert_data['index'],
                                other_parent_data=parent_data)
        else:
            vert('parent_id' in data, 'assignment offer missing parent_id')
            vert('coords' in data, 'assignment offer missing coords')
            vert('index' in data, 'assignment offer missing index')
            vert('root' in data, 'assignment offer missing root')
            parent_id = b64decode(data['parent_id'])
            coords = data['coords']
            index = data['index']
            root = b64decode(data['root'])
            if root != self.root:
                if self.try_elect_root(root):
                    self.set_parent(parent_id, coords, index)

    def _handle_request_assignment(self, message: PIEMessage, msgbody: PIEMsgBody) -> None:
        """Handle an assignment request."""
        body = json.loads(msgbody.body)
        if 'auth_base' in self.config:
            if not _functions['check_auth'] or 'auth' not in body:
                return
            if not _functions['check_auth'](
                b64decode(self.config['auth_base']),
                message.src_id,
                b64decode(body['auth'])
            ):
                self.send_error_message(message.src, message.src_id, b'invalid auth')
                return
        if 'use_certs' in self.config:
            msg = self._make_offer_assignment_msg(
                message.src_id, message.src, {
                    'cert': self.assignment_cert,
                }
            )
        else:
            msg = self._make_offer_assignment_msg(message.src_id, message.src)

        msg.flow_label = message.flow_label
        seq = message.seq + 1
        msg.seq = seq if seq <= 255 else 0

        try:
            self.send_message(msg, message.src_id)
        except UnicastException:
            ...

    def _handle_accept_assignment(self, message: PIEMessage, msgbody: PIEMsgBody) -> None:
        """Handle an ACCEPT_ASSIGNMENT message from new child."""
        body = json.loads(msgbody.body)
        if bytes.fromhex(body['parent_id']) != self.tree.node_id:
            return
        if 'cert' in body and 'use_certs' in self.config:
            if not self.check_cert(body['cert']):
                return
            if body['cert']['parent_id'] != b64encode(self.tree.node_id).decode('utf-8'):
                return
        else:
            if 'use_certs' in self.config:
                return
        if body['root'] != self.root:
            return
        self.add_child(message.src_id, body)

    def _handle_announce_assignment(self, message: PIEMessage, msgbody: PIEMsgBody) -> None:
        """Handle an ANNOUNCE_ASSIGNMENT message from neighbor."""
        body = json.loads(msgbody.body)
        if 'auth_base' in self.config:
            if not _functions['check_auth'] or 'auth' not in body:
                return
            if not _functions['check_auth'](
                b64decode(self.config['auth_base']),
                message.src_id,
                b64decode(body['auth'])
            ):
                self.send_error_message(message.src, message.src_id, b'invalid auth')
                return
        if 'cert' in body and 'use_certs' in self.config:
            if not self.check_cert(b64decode(body['cert'])):
                return
            cert = json.loads(b64decode(body['cert']))
            if cert['parent_id'] != b64encode(self.tree.node_id).decode('utf-8'):
                return
        else:
            if 'use_certs' in self.config:
                return
        if body['root'] != self.root:
            return
        self.add_neighbor(message.src_id, body)

    def _handle_release_assignment(self, message: PIEMessage, msgbody: PIEMsgBody) -> None:
        """Handle an RELEASE_ASSIGNMENT message from child or neighbor."""
        body = json.loads(msgbody.body)
        coords = body['coords'] if 'coords' in body else []
        if msgbody.sig and not msgbody.check_sig(message.src_id):
            return
        if message.src_id in self.child_coords:
            if self.child_coords[message.src_id] == coords:
                return self.remove_child(message.src_id)
        if message.src_id in self.neighbor_coords:
            if self.neighbor_coords[message.src_id] == coords:
                return self.remove_neighbor(message.src_id)

    def send_error_message(self, dst: list[int], dst_id: bytes,
                           msgtype: PIEMsgType, msg: bytes = b'') -> None:
        """Send an error message to the given destination."""
        msgbody = PIEMsgBody(msg)
        msgbody.sign(self.skey)
        message = PIEMessage(
            msgtype,
            self.id,
            dst,
            dst_id,
            self.local_coords,
            self.tree.node_id,
            msgbody.to_bytes(),
            bifurcations=self.route_table.get_bifurcations(self.id, dst)
        )
        self.route_message(message)

    def send_message(self, message: PIEMessage, peer_id: bytes,
                     peer_coords: list[int] = []) -> None:
        """Send a message to a specific peer."""
        self.invoke_hook(
            PIEEvent.SEND_MESSAGE,
            {
                'message': message,
                'peer_coords': peer_coords,
                'peer_id': peer_id
            }
        )

        for sender in self.senders:
            if isinstance(sender, CanUnicast):
                if sender.unicast(message, peer_id, peer_coords):
                    return

        raise UnicastException(peer_id)

    def multicast(self, message: PIEMessage) -> None:
        """Multicast a message to all subscribed peers."""
        self.invoke_hook(
            PIEEvent.MULTICAST_MESSAGE,
            {
                'message': message,
            }
        )

        for sender in self.senders:
            if isinstance(sender, CanMulticast):
                sender.multicast(message)

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
                new_coords.append(link_weight)
            else:
                new_coords.append(-link_weight)
        return new_coords

    def to_json(self) -> str:
        """Returns a json str encoding the instance data."""
        tree = b64encode(self.tree.to_json()).decode('utf-8')
        table = b64encode(self.route_table.to_json()).decode('utf-8')
        return json.dumps({
            'id': self.id.hex(),
            'config': self.config,
            'root': self.root,
            'skey': self.skey.hex(),
            'tree': tree,
            'locality_level': self.locality_level,
            'local_coords': self.local_coords,
            'child_coordinates': {
                cid.hex(): coords
                for cid, coords in self.child_coords.items()
            },
            'neighbor_coords': {
                nid.hex(): coords
                for nid, coords in self.neighbor_coords.items()
            },
            'route_table': table,
        })

    @classmethod
    def from_json(cls, data: str|bytes) -> PIETree:
        """Returns an instance with data deserialized from json."""
        unpacked = json.loads(data)
        child_coords = {
            bytes.fromhex(cid): coords
            for cid, coords in unpacked['child_coordinates']
        }
        neighbor_coords = {
            bytes.fromhex(nid): coords
            for nid, coords in unpacked['neighbor_coordinates']
        }
        table = SrcAidedRouteTable.from_json(b64decode(unpacked['route_table']))
        return cls(
            id=bytes.fromhex(unpacked['id']),
            config=unpacked['config'],
            root=unpacked['root'],
            skey=bytes.fromhex(unpacked['skey']),
            tree=LocalTree.from_json(b64decode(unpacked['tree'])),
            locality_level=unpacked['locality_level'],
            local_coords=unpacked['local_coords'],
            child_coords=child_coords,
            neighbor_coords=neighbor_coords,
            route_table=table,
        )
