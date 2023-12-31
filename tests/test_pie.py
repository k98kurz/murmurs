from base64 import b64encode, b64decode
from context import errors, pie, spanningtree
from hashlib import sha256
from nacl.signing import SigningKey, VerifyKey
from secrets import token_bytes
import unittest


class TestPIEFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._functions = {**pie._functions}
        return super().setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        pie._functions = cls._functions
        return super().tearDownClass()

    def test_set_sign_function(self):
        func = lambda b1, b2: b1+b2
        assert pie._functions['sign'] is not func
        pie.set_sign_function(func)
        assert pie._functions['sign'] is func

    def test_set_check_sig_function(self):
        func = lambda b1, b2, b3: b1==b2==b3
        assert pie._functions['check_sig'] is not func
        pie.set_check_sig_function(func)
        assert pie._functions['check_sig'] is func

    def test_set_elect_root_func(self):
        func = lambda b1, b2, i: len(b1) == len(b2) == i
        assert pie._functions['elect_root'] is not func
        pie.set_elect_root_func(func)
        assert pie._functions['elect_root'] is func

    def test_set_make_auth_func(self):
        func = lambda b1, b2, i: len(b1) == len(b2) == i
        assert pie._functions['make_auth'] is not func
        pie.set_make_auth_func(func)
        assert pie._functions['make_auth'] is func

    def test_set_check_auth_func(self):
        func = lambda b1, b2, i: len(b1) == len(b2) == i
        assert pie._functions['check_auth'] is not func
        pie.set_check_auth_func(func)
        assert pie._functions['check_auth'] is func

    def test_signed_int_to_bytes(self):
        b1 = pie.signed_int_to_bytes(11)
        b2 = pie.signed_int_to_bytes(-11)
        b3 = pie.signed_int_to_bytes(1000)

        assert type(b1) is type(b2) is type(b3) is bytes
        assert len(b1) == len(b2) == 1
        assert b1 != b2
        assert len(b3) == 2

    def test_int_to_1_byte(self):
        b1 = pie.int_to_1_byte(11)
        b2 = pie.int_to_1_byte(-11)
        b3 = pie.int_to_1_byte(100)

        assert type(b1) is type(b2) is type(b3) is bytes
        assert len(b1) == len(b2) == len(b3) == 1
        assert b1 != b2
        assert b1 != b3
        assert b2 != b3

        with self.assertRaises(OverflowError):
            pie.int_to_1_byte(1000)

    def test_bytes_to_int(self):
        i1 = pie.bytes_to_int(b'\xff\x00')
        i2 = pie.bytes_to_int(b'\xff\xff')
        i3 = pie.bytes_to_int(b'\x10\x00\x00')

        assert type(i1) is type(i2) is type(i3) is int
        assert i1 != i2
        assert i1 != i3
        assert i2 != i3

    def test_bytes_int_conversions_e2e(self):
        ints = list(range(-128, 128))
        bts = []
        for i in ints:
            bts.append(pie.int_to_1_byte(i))

        decoded = [pie.bytes_to_int(b) for b in bts]
        assert decoded == ints

    def test_encode_coordinates_and_decode_coordinates_e2e(self):
        coords = [5, -4, -3, 2, -2, 1]
        encoded = pie.encode_coordinates(coords)
        assert type(encoded) is bytes
        assert len(encoded) % 2 == 0
        decoded = pie.decode_coordinates(encoded)
        assert type(decoded) is list
        assert all(type(d) is int for d in decoded)
        assert decoded == coords

    def test_encode_small_coordinates_and_decode_small_coordinates_e2e(self):
        coords = [5, -4, -3, 2, -2, 1]
        encoded = pie.encode_small_coordinates(coords)
        assert type(encoded) is bytes
        assert len(encoded) == len(coords)
        decoded = pie.decode_small_coordinates(encoded)
        assert type(decoded) is list
        assert all(type(d) is int for d in decoded)
        assert decoded == coords

    def test_encode_big_coordinates_and_decode_big_coordinates_e2e(self):
        coords1 = [555555, -444, -3, 2, -2, 1]
        coords2 = [5, -4, -3, 2, -2, 1]
        encoded = pie.encode_big_coordinates(coords1)
        assert type(encoded) is bytes
        decoded = pie.decode_big_coordinates(encoded)
        assert type(decoded) is list
        assert all(type(d) is int for d in decoded)
        assert decoded == coords1
        encoded2 = pie.encode_big_coordinates(coords2)
        assert len(encoded) != len(encoded2)
        assert pie.decode_big_coordinates(encoded2) == coords2

    def test_encode_coordinates_saves_space_for_high_connectivity(self):
        """Networks/graphs with high connectivity have long child
            indices, which means many coordinates of repeated magnitude.
            The encode_coordinates function compacts coordinate groups
            sharing magnitude into two bytes per 7 coords.
        """
        coords = [5, -5, -5, 4, 4, -3, -3, 3, 2, -2, -2, 2, 1, -1]
        encoded1 = pie.encode_coordinates(coords)
        encoded2 = pie.encode_small_coordinates(coords)
        encoded3 = pie.encode_big_coordinates(coords)

        assert len(encoded1) < len(encoded2) < len(encoded3)

    def test_encode_small_coordinates_saves_space_for_low_connectivity(self):
        """Networks/graphs with low connectivity have short child
            indices, which means few coordinates of repeated magnitude.
            The encode_small_coordinates function compacts each coord
            into a single byte with maximum magnitude of 127.
        """
        coords = [8, -7, -6, 5, -4, 3, -2, 1]
        encoded1 = pie.encode_small_coordinates(coords)
        encoded2 = pie.encode_coordinates(coords)
        encoded3 = pie.encode_big_coordinates(coords)

        assert len(encoded1) < len(encoded2) < len(encoded3)

    def test_encode_big_coordinates_can_encode_coords_that_other_encodings_cannot(self):
        """Networks/graphs with paths with greater than 255 hops or that
            use link weights greater than 1 must use
            encode_big_coordinates to encode coordinates.
        """
        coords = [300, -299, 299, 288, -270, 120, -110, -82, 33, 13, -5]
        encoded1 = pie.encode_big_coordinates(coords)
        decoded1 = pie.decode_big_coordinates(encoded1)
        assert decoded1 == coords

        with self.assertRaises(OverflowError) as e:
            pie.encode_coordinates(coords)
        assert str(e.exception) == 'int too big to convert'

        with self.assertRaises(OverflowError) as e:
            pie.encode_small_coordinates(coords)
        assert str(e.exception) == 'int too big to convert'


class TestPIEMessage(unittest.TestCase):
    def test_encode_header_and_decode_header_e2e(self):
        treeid = b'some tree'
        dst = [5, -4, 3, -2, 2, 1]
        dst_id = b'destination'
        src = [4, 3, -3, -2, 1, -1]
        src_id = b'source'
        bifurcations = [
            [5, -4, -3, 2, -1],
            [-5, -4, -3, 2, -1],
        ]
        body = b'hello world'
        seq = 12
        msg = pie.PIEMessage(
            pie.PIEMsgType.DEFAULT,
            treeid,
            dst,
            dst_id,
            src,
            src_id,
            body,
            bifurcations,
            seq=seq,
        )
        flow_label = msg.flow_label
        ttl = msg.ttl

        encoded = msg.encode_header()
        assert type(encoded) is bytes
        assert len(encoded)

        decoded = pie.PIEMessage.decode_header(encoded)
        assert type(decoded) is tuple
        assert decoded[0] == pie.PIEMsgType.DEFAULT
        assert decoded[1] == treeid
        assert decoded[2] == dst
        assert decoded[3] == dst_id
        assert decoded[4] == src
        assert decoded[5] == src_id
        assert decoded[6] == bifurcations
        assert decoded[7] == ttl
        assert decoded[8] == flow_label
        assert decoded[9] == seq

    def test_encode_header_and_decode_header_with_big_coords_e2e(self):
        treeid = b'some tree'
        dst = [5, -4, 3, -2, 2, 1]
        dst_id = b'destination'
        src = [4, 3, -3, -2, 1, -1]
        src_id = b'source'
        bifurcations = [
            [5, -4, -3, 2, -1],
            [-5, -4, -3, 2, -1],
        ]
        body = b'hello world'
        seq = 12
        msg = pie.PIEMessage(
            pie.PIEMsgType.DEFAULT,
            treeid,
            dst,
            dst_id,
            src,
            src_id,
            body,
            bifurcations,
            seq=seq,
        )
        ttl = msg.ttl
        flow_label = msg.flow_label

        encoded = msg.encode_header(True)
        assert type(encoded) is bytes
        assert len(encoded)

        decoded = pie.PIEMessage.decode_header(encoded, True)
        assert type(decoded) is tuple
        assert decoded[0] == pie.PIEMsgType.DEFAULT
        assert decoded[1] == treeid
        assert decoded[2] == dst
        assert decoded[3] == dst_id
        assert decoded[4] == src
        assert decoded[5] == src_id
        assert decoded[6] == bifurcations
        assert decoded[7] == ttl
        assert decoded[8] == flow_label
        assert decoded[9] == seq

    def test_to_bytes_and_from_bytes_e2e(self):
        treeid = b'some tree'
        dst = [5, -4, 3, -2, 2, 1]
        src = [4, 3, -3, -2, 1, -1]
        dst_id = b'destination'
        src_id = b'source'
        bifurcations = [
            [5, -4, -3, 2, -1],
            [-5, -4, -3, 2, -1],
        ]
        body = b'hello world'
        seq = 12
        msg = pie.PIEMessage(
            pie.PIEMsgType.DEFAULT,
            treeid,
            dst,
            dst_id,
            src,
            src_id,
            body,
            bifurcations,
            seq=seq,
        )

        encoded = msg.to_bytes()
        assert type(encoded) is bytes
        assert len(encoded)

        decoded = pie.PIEMessage.from_bytes(encoded)
        assert isinstance(decoded, pie.PIEMessage)
        assert decoded.treeid == msg.treeid
        assert decoded.dst == msg.dst
        assert decoded.dst_id == msg.dst_id
        assert decoded.src_id == msg.src_id
        assert decoded.bifurcations == msg.bifurcations
        assert decoded.body == msg.body
        assert decoded.seq == msg.seq == seq

    def test_to_bytes_and_from_bytes_with_big_coords_e2e(self):
        treeid = b'some tree'
        dst = [5, -4, 3, -2, 2, 1]
        dst_id = b'destination'
        src = [4, 3, -3, -2, 1, -1]
        src_id = b'source'
        bifurcations = [
            [5, -4, -3, 2, -1],
            [-5, -4, -3, 2, -1],
        ]
        body = b'hello world'
        seq = 12
        msg = pie.PIEMessage(
            pie.PIEMsgType.DEFAULT,
            treeid,
            dst,
            dst_id,
            src,
            src_id,
            body,
            bifurcations,
            seq=seq,
        )

        encoded = msg.to_bytes(True)
        assert type(encoded) is bytes
        assert len(encoded)

        decoded = pie.PIEMessage.from_bytes(encoded, True)
        assert isinstance(decoded, pie.PIEMessage)
        assert decoded.treeid == msg.treeid
        assert decoded.dst == msg.dst
        assert decoded.dst_id == msg.dst_id
        assert decoded.src == msg.src
        assert decoded.src_id == msg.src_id
        assert decoded.bifurcations == msg.bifurcations
        assert decoded.body == msg.body
        assert decoded.seq == msg.seq == seq

    def test_header_id_is_unique_and_deterministic_for_each_header_and_disregards_ttl(self):
        treeid = b'some tree'
        dst1 = [5, -4, 3, -2, 2, 1]
        dst2 = [-5, 4, 3, 2, -1]
        src = [4, 3, -3, -2, 1, -1]
        dst1_id = b'dst1'
        dst2_id = b'dst2'
        src_id = b'src'
        body1 = b'hello world'
        flow_label1 = b'1234'
        flow_label2 = b'abcd'
        msg1 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst1, dst1_id,
                              src, src_id, body1, flow_label=flow_label1, ttl=255)
        msg11 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst1, dst1_id,
                              src, src_id, body1, flow_label=flow_label1, ttl=12)
        msg2 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst2, dst2_id,
                               src, src_id, body1, flow_label=flow_label2, ttl=1)
        msg22 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst2, dst2_id,
                               src, src_id, body1, flow_label=flow_label2, ttl=20)

        assert type(msg1.header_id()) is bytes
        assert msg1.header_id() == msg1.header_id()
        assert msg1.header_id() == msg11.header_id()
        assert msg2.header_id() == msg2.header_id()
        assert msg2.header_id() == msg22.header_id()
        assert msg1.header_id() != msg2.header_id()

    def test_body_id_is_unique_and_deterministic_for_each_body(self):
        treeid = b'some tree'
        dst1 = [5, -4, 3, -2, 2, 1]
        dst2 = [-5, 4, 3, 2, -1]
        src = [4, 3, -3, -2, 1, -1]
        dst1_id = b'dst1'
        dst2_id = b'dst2'
        src_id = b'src'
        body1 = b'hello world'
        body2 = b'yello world'
        msg1 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst1, dst1_id,
                              src, src_id, body1)
        msg11 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst2, dst2_id,
                               src, src_id, body1)
        msg2 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst1, dst1_id,
                               src, src_id, body2)
        msg22 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst2, dst2_id,
                               src, src_id, body2)

        assert type(msg1.body_id()) is bytes
        assert msg1.body_id() == msg1.body_id()
        assert msg1.body_id() == msg11.body_id()
        assert msg2.body_id() == msg2.body_id()
        assert msg2.body_id() == msg22.body_id()

    def test_msg_id_is_unique_and_deterministic_for_each_msg(self):
        treeid = b'some tree'
        dst1 = [5, -4, 3, -2, 2, 1]
        dst2 = [-5, 4, 3, 2, -1]
        src = [4, 3, -3, -2, 1, -1]
        dst1_id = b'dst1'
        dst2_id = b'dst2'
        src_id = b'src'
        body1 = b'hello world'
        body2 = b'yello world'
        msg1 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst1, dst1_id,
                              src, src_id, body1)
        msg11 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst2, dst2_id,
                              src, src_id, body1)
        msg2 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst1, dst1_id,
                              src, src_id, body2)
        msg22 = pie.PIEMessage(pie.PIEMsgType.DEFAULT, treeid, dst2, dst2_id,
                              src, src_id, body2)

        assert type(msg1.msg_id()) is bytes
        assert msg1.msg_id() == msg1.msg_id()
        assert msg1.msg_id() != msg11.msg_id()
        assert msg2.msg_id() == msg2.msg_id()
        assert msg2.msg_id() != msg22.msg_id()
        assert msg11.msg_id() != msg22.msg_id()


class TestPIEMsgBody(unittest.TestCase):
    def test_sign_works_with_set_function(self):
        pie.set_sign_function(lambda b1, b2: b1 + b':' + b2)
        msgbody = pie.PIEMsgBody(b'some body')
        assert msgbody.sig == b''
        msgbody.sign(b'privkey')
        assert msgbody.sig == b'privkey:some body'

    def test_check_sig_works_with_set_function(self):
        skey = b'privkey'
        body = b'some body'
        msgbody = pie.PIEMsgBody(body, skey + b':' + body)
        checked = msgbody.check_sig(skey)
        assert checked is None
        pie.set_check_sig_function(lambda b1, b2, b3: b1 + b':' + b2 == b3)
        checked = msgbody.check_sig(skey)
        assert type(checked) is bool
        assert checked

    def test_to_bytes_and_from_bytes_e2e(self):
        msgbody = pie.PIEMsgBody(b'some body', b'some sig')

        encoded = msgbody.to_bytes()
        assert type(encoded) is bytes
        decoded = pie.PIEMsgBody.from_bytes(encoded)
        assert type(decoded) is pie.PIEMsgBody
        assert decoded.body == msgbody.body == b'some body'
        assert decoded.sig == msgbody.sig == b'some sig'

        msgbody = pie.PIEMsgBody(b'some body')

        encoded = msgbody.to_bytes()
        assert type(encoded) is bytes
        decoded = pie.PIEMsgBody.from_bytes(encoded)
        assert type(decoded) is pie.PIEMsgBody
        assert decoded.body == msgbody.body == b'some body'
        assert decoded.sig == msgbody.sig == b''

        msgbody = pie.PIEMsgBody(b'', b'some sig')

        encoded = msgbody.to_bytes()
        assert type(encoded) is bytes
        decoded = pie.PIEMsgBody.from_bytes(encoded)
        assert type(decoded) is pie.PIEMsgBody
        assert decoded.body == msgbody.body == b''
        assert decoded.sig == msgbody.sig == b'some sig'

        msgbody = pie.PIEMsgBody(b'')

        encoded = msgbody.to_bytes()
        assert type(encoded) is bytes
        decoded = pie.PIEMsgBody.from_bytes(encoded)
        assert type(decoded) is pie.PIEMsgBody
        assert decoded.body == msgbody.body == b''
        assert decoded.sig == msgbody.sig == b''


class FakeSender:
    sent: list[pie.PIEMessage]
    def __init__(self) -> None:
        self.sent = []
    def unicast(self, message: pie.PIEMessage, dst: list[int], route_data: dict = None) -> bool:
        self.sent.append(message)
        return True


class UnicastSender:
    trees: list[pie.PIETree]
    def __init__(self) -> None:
        self.trees = []
    def unicast(self, message: pie.PIEMessage, dst: bytes, route_data: dict = None) -> bool:
        for tree in self.trees:
            tree.receive_message(message)
        return True


class MulticastSender:
    trees: list[pie.PIETree]
    def __init__(self) -> None:
        self.trees = []
    def multicast(self, message: pie.PIEMessage) -> bool:
        for tree in self.trees:
            tree.receive_message(message)
        return True


class TestPIETree(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._functions = {**pie._functions}
        return super().setUpClass()

    def tearDown(cls) -> None:
        pie._functions = cls._functions
        return super().tearDown()

    def test_set_hook_replaces_hook(self):
        tree = pie.PIETree()
        signal = {}
        def hook1(event: pie.PIEEvent, data: dict):
            signal['event'] = event
            signal['data'] = data
        def hook2(event: pie.PIEEvent, data: dict):
            signal['event'] = 'replaced'
            signal['data'] = 'replaced'
        tree.set_hook(pie.PIEEvent.RECEIVE_MESSAGE, hook1)

        assert 'event' not in signal
        assert 'data' not in signal
        tree.invoke_hook(pie.PIEEvent.RECEIVE_MESSAGE, {'some_data': 'whatever'})
        assert 'event' in signal
        assert 'data' in signal
        assert 'some_data' in signal['data']
        assert 'tree' in signal['data']
        assert signal['data']['tree'] is tree

        tree.set_hook(pie.PIEEvent.RECEIVE_MESSAGE, hook2)
        tree.invoke_hook(pie.PIEEvent.RECEIVE_MESSAGE, {})
        assert signal['event'] == 'replaced'
        assert signal['data'] == 'replaced'

    def test_add_hook_executes_multiple_handlers_in_order(self):
        tree = pie.PIETree()
        signal = {}
        def hook1(event: pie.PIEEvent, data: dict):
            signal['event'] = 'hook1'
            return data
        def hook2(event: pie.PIEEvent, data: dict):
            signal['data'] = data
            return data
        tree.add_hook(pie.PIEEvent.DELIVER_PACKET, hook1)
        tree.add_hook(pie.PIEEvent.DELIVER_PACKET, hook2)

        assert 'event' not in signal
        assert 'data' not in signal
        tree.invoke_hook(pie.PIEEvent.DELIVER_PACKET, {'some_data': 'whatever'})
        assert 'event' in signal
        assert 'data' in signal
        assert signal['event'] == 'hook1'
        assert signal['data']['tree'] is tree

    def test_add_sender_raises_TypeError_for_instance_not_implementing_CanUnicast(self):
        tree = pie.PIETree()
        with self.assertRaises(TypeError) as e:
            tree.add_sender({'not': 'CanUnicast'})
        assert str(e.exception) == 'sender must implement CanUnicast'

    def test_send_message_raises_error_if_no_sender_can_send(self):
        tree = pie.PIETree()
        peer_id = b'some node'
        dst = [-2, 1]
        message = pie.PIEMessage(
            pie.PIEMsgType.ECHO,
            tree.id,
            dst,
            b'dst_id',
            [-3, 2, 1],
            b'src_id',
            b'olleh'
        )

        with self.assertRaises(errors.UnicastException) as e:
            tree.send_message(message, peer_id)
        assert str(e.exception) == f'could not unicast to peer_id={peer_id.hex()}'

    def test_add_sender_causes_sender_unicast_to_be_invoked_on_send(self):
        sender = FakeSender()
        tree = pie.PIETree()
        peer_id = b'some node'
        dst = [-2, 1]
        message = pie.PIEMessage(
            pie.PIEMsgType.ECHO,
            tree.id,
            dst,
            b'dst_id',
            [-3, 2, 1],
            b'src_id',
            b'olleh'
        )
        tree.add_sender(sender)
        assert not len(sender.sent)
        tree.send_message(message, dst, peer_id)
        assert len(sender.sent)
        assert sender.sent == [message]

    def test_set_parent_sets_parent_and_invokes_hooks(self):
        signal = {}
        def hook1(event, data) -> dict:
            signal['hook1'] = event
            return data
        def hook2(event, data) -> dict:
            signal['hook2'] = event
            return data
        def hook3(event, data) -> dict:
            signal['hook3'] = event
            return data
        def hook4(event, data) -> dict:
            signal['hook4'] = event
            return data

        tree = pie.PIETree()
        tree.add_sender(FakeSender())
        tree.add_hook(pie.PIEEvent.BEFORE_SET_PARENT, hook1)
        tree.add_hook(pie.PIEEvent.AFTER_SET_PARENT, hook3)
        tree.tree.add_hook(spanningtree.SpanningTreeEvent.BEFORE_SET_PARENT, hook2)
        tree.tree.add_hook(spanningtree.SpanningTreeEvent.AFTER_SET_PARENT, hook4)

        assert 'hook1' not in signal
        assert 'hook2' not in signal
        assert 'hook3' not in signal
        assert 'hook4' not in signal
        assert tree.tree.parent_id != b'parent'
        tree.set_parent(b'parent', [-1], '101')
        assert 'hook1' in signal
        assert 'hook2' in signal
        assert 'hook3' in signal
        assert 'hook4' in signal
        assert tree.tree.parent_id == b'parent'

    def test_set_parent_sends_messages(self):
        tree = pie.PIETree()
        sender = FakeSender()
        tree.add_sender(sender)
        tree.local_coords = [2, -1]

        parent_id = b'parent'
        parent_coords = [-2, 1]
        children = {
            b'child1': [3, -2, 1],
            b'child2': [3, -2, -1],
        }
        neighbors = {
            b'neighbor1': [4, 3, 2, 1, 1],
            b'neighbor2': [4, 3, 2, 1, -1],
            b'neighbor3': [-2, 1],
        }

        for cid, coords in children.items():
            tree.add_child(cid)
            assert tree.child_coords[cid] == coords

        for nid, coords in neighbors.items():
            tree.add_neighbor(nid, {'coords': coords})

        assert not sender.sent
        tree.set_parent(parent_id, parent_coords, '10')
        assert sender.sent
        n_sent_to_parent = 0
        n_sent_to_children = 0
        n_sent_to_neighbors = 0
        for msg in sender.sent:
            match msg.msg_type:
                case pie.PIEMsgType.ACCEPT_ASSIGNMENT:
                    assert msg.dst_id == parent_id
                    n_sent_to_parent += 1
                case pie.PIEMsgType.OFFER_ASSIGNMENT:
                    assert msg.dst_id in children
                    n_sent_to_children += 1
                case pie.PIEMsgType.ANNOUNCE_ASSIGNMENT:
                    assert msg.dst_id in neighbors
                    n_sent_to_neighbors += 1
                case _:
                    assert False
        assert n_sent_to_parent == 1
        assert n_sent_to_children == 2
        assert n_sent_to_neighbors == 3

    def test_small_network_construction_e2e(self):
        """Tests a network with this structure:
            node 0 connects to 1 and 2
            node 1 connects to 0 and 3
            node 2 connects to 0 and 3
            node 3 connects to 1 and 2
        """
        def distance(b1: bytes, b2: bytes) -> int:
            while len(b1) > len(b2):
                b2 = b2 + b'\x00'
            while len(b2) > len(b1):
                b1 = b1 + b'\x00'
            diff = 0
            for i in range(len(b1)):
                diff += b1[i] ^ b2[i]
            return diff

        def elect_root(current: bytes, candidate: bytes, locality_level: int):
            if not current:
                return True
            target = bytes.fromhex('df9908d772d0d0345a58ef0e8b5188e62d7b85a392428155af7c83a37c1af2f8')
            return distance(candidate, target) < distance(current, target)

        def sign(skey: bytes, msg: bytes) -> bytes:
            return SigningKey(skey).sign(msg)[:64]

        def check_sig(vkey: bytes, msg: bytes, sig: bytes) -> bool:
            try:
                VerifyKey(vkey).verify(msg, sig)
                return True
            except:
                return False

        def make_auth(base: bytes, node_id: bytes, skey: bytes = b'') -> bytes:
            return sha256(base + node_id).digest()[:8]

        def check_auth(base: bytes, node_id: bytes, data: bytes) -> bytes:
            return data == sha256(base + node_id).digest()[:8]

        pie.set_elect_root_func(elect_root)
        pie.set_sign_function(sign)
        pie.set_check_sig_function(check_sig)
        pie.set_make_auth_func(make_auth)
        pie.set_check_auth_func(check_auth)

        node_skeys = [
            bytes.fromhex('d84fb53be55ec5ee671bc638da27e1afc08eb675a1d43edb39614c4c4922adbb'),
            bytes.fromhex('4fced22f2809448393ca63e34612daf67eb0480522d1f94299c906e51ad1560f'),
            bytes.fromhex('a1b42ee0db9cd6838febc35e6125f78b0c92fed07cfaa7b32d81eac11a18e1b6'),
            bytes.fromhex('22fb681265056986ebe6008e4baff6ff90613a42204adee9a01e3ac52ff256b6'),
        ]
        node_ids = [bytes(SigningKey(nsk).verify_key) for nsk in node_skeys]
        config = {
            'use_certs': True,
            'auth_base': b64encode(b'1234').decode('utf-8')
        }
        trees = [
            pie.PIETree(config=config, skey=node_skeys[i], node_id=node_ids[i])
            for i in range(len(node_ids))
        ]
        senders = [UnicastSender() for _ in node_ids]
        multicasters = [MulticastSender() for _ in node_ids]

        # node 0 connects to 1 and 2
        senders[0].trees.append(trees[1])
        senders[0].trees.append(trees[2])
        multicasters[0].trees.append(trees[1])
        multicasters[0].trees.append(trees[2])
        # node 1 connects to 0 and 3
        senders[1].trees.append(trees[0])
        senders[1].trees.append(trees[3])
        multicasters[1].trees.append(trees[0])
        multicasters[1].trees.append(trees[3])
        # node 2 connects to 0 and 3
        senders[2].trees.append(trees[0])
        senders[2].trees.append(trees[3])
        multicasters[2].trees.append(trees[0])
        multicasters[2].trees.append(trees[3])
        # node 3 connects to 1 and 2
        senders[3].trees.append(trees[1])
        senders[3].trees.append(trees[2])
        multicasters[3].trees.append(trees[1])
        multicasters[3].trees.append(trees[2])

        # elect each as root independently
        for tree in trees:
            tree.try_elect_root(tree.tree.node_id)

        # announce for peer discovery
        for i in range(len(trees)):
            message = trees[i].make_hello()
            multicasters[i].multicast(message)

        # attempt to equalize network with rounds of communication
        # for _ in range(5):
        #     for tree in trees:
        #         # anounce current config to each peer
        #         tree.multicast(tree.make_hello())


if __name__ == '__main__':
    unittest.main()
