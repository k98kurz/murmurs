from context import errors, pie, spanningtree
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

    def test_set_checksig_function(self):
        func = lambda b1, b2, b3: b1==b2==b3
        assert pie._functions['check_sig'] is not func
        pie.set_checksig_function(func)
        assert pie._functions['check_sig'] is func

    def test_set_elect_root_func(self):
        func = lambda b1, b2, i: len(b1) == len(b2) == i
        assert pie._functions['elect_root'] is not func
        pie.set_elect_root_func(func)
        assert pie._functions['elect_root'] is func

    def test_set_send_message_func(self):
        func = lambda pm: pm
        assert pie._functions['send_message'] is not func
        pie.set_send_message_func(func)
        assert pie._functions['send_message'] is func

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
        assert len(encoded) == len(coords)
        decoded = pie.decode_coordinates(encoded)
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


class Sender:
    sent: list[pie.PIEMessage]
    def __init__(self) -> None:
        self.sent = []
    def unicast(self, message: pie.PIEMessage, dst: list[int], route_data: dict = None) -> bool:
        self.sent.append(message)
        return True


class TestPIETree(unittest.TestCase):
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
            tree.send_message(message, [-2, 1], peer_id)
        assert str(e.exception) == f'could not unicast to peer_id={peer_id.hex()}'

    def test_add_sender_causes_sender_unicast_to_be_invoked_on_send(self):
        sender = Sender()
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
        tree.add_sender(Sender())
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
        sender = Sender()
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


if __name__ == '__main__':
    unittest.main()
