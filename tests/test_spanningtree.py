from context import spanningtree
from enum import Enum
from secrets import token_bytes
import unittest


class TestSpanningTree(unittest.TestCase):
    def test_spanningtree_has_SpanningTreeEvent_and_LocalTree(self):
        assert hasattr(spanningtree, 'SpanningTreeEvent')
        assert issubclass(spanningtree.SpanningTreeEvent, Enum)
        assert hasattr(spanningtree, 'LocalTree')

    def test_LocalTree_set_parent_works(self):
        parent_id = b'parent'
        node_id = b'some node'
        tree = spanningtree.LocalTree(node_id=node_id)

        assert not tree.parent_id
        assert not tree.parent_data
        tree.set_parent(parent_id, {'id': parent_id})
        assert tree.parent_id == parent_id
        assert 'id' in tree.parent_data and tree.parent_data['id'] == parent_id

    def test_LocalTree_add_child_and_remove_child_work(self):
        node_id = b'some node'
        child_id = b'child'
        tree = spanningtree.LocalTree(node_id=node_id)

        assert not tree.child_ids
        assert not tree.child_data
        tree.add_child(child_id, {'id': child_id})
        assert child_id in tree.child_ids
        assert child_id in tree.child_data
        assert 'id' in tree.child_data[child_id]
        assert tree.child_data[child_id]['id'] == child_id
        tree.remove_child(child_id)
        assert child_id not in tree.child_ids
        assert child_id not in tree.child_data

    def test_LocalTree_reuses_child_indices(self):
        node_id = b'some node'
        child_id1 = b'child1'
        child_id2 = b'child2'
        child_id3 = b'child3'
        tree = spanningtree.LocalTree(node_id=node_id)
        tree.add_child(child_id1)
        index1 = tree.child_ids.index(child_id1)
        tree.add_child(child_id2)
        index2 = tree.child_ids.index(child_id2)
        tree.remove_child(child_id1)
        tree.add_child(child_id3)
        index3 = tree.child_ids.index(child_id3)

        assert index1 != index2
        assert index1 == index3

    def test_LocalTree_add_neighbor_and_remove_neighbor_work(self):
        neighbor_id = b'neighbor'
        node_id = b'some node'
        tree = spanningtree.LocalTree(node_id=node_id)

        assert neighbor_id not in tree.neighbor_ids
        assert neighbor_id not in tree.neighbor_data
        tree.add_neighbor(neighbor_id, {'id': neighbor_id})
        assert neighbor_id in tree.neighbor_ids
        assert neighbor_id in tree.neighbor_data
        assert 'id' in tree.neighbor_data[neighbor_id]
        assert tree.neighbor_data[neighbor_id]['id'] == neighbor_id
        tree.remove_neighbor(neighbor_id)
        assert neighbor_id not in tree.neighbor_ids
        assert neighbor_id not in tree.neighbor_data

    def test_LocalTree_add_hook_executes_multiple_handlers_in_order(self):
        info = {
            'count': 0,
            'first': -1,
            'second': -1
        }

        def first(event, data):
            print()
            info['count'] += 1
            info['first'] = info['count']

        def second(event, data):
            info['count'] += 1
            info['second'] = info['count']

        tree = spanningtree.LocalTree()
        tree.add_hook(
            spanningtree.SpanningTreeEvent.BEFORE_ADD_CHILD,
            first
        )
        tree.add_hook(
            spanningtree.SpanningTreeEvent.BEFORE_ADD_CHILD,
            second
        )

        assert info['first'] == -1
        assert info['second'] == -1
        tree.invoke_hook(spanningtree.SpanningTreeEvent.BEFORE_ADD_CHILD, {})
        assert info['first'] == 1
        assert info['second'] == 2

    def test_LocalTree_hooks_for_set_parent_events(self):
        signal = {
            'before': False,
            'after': False,
        }
        def before(event, data):
            signal['before'] = data
        def after(event, data):
            signal['after'] = data

        tree = spanningtree.LocalTree()
        tree.set_hook(
            spanningtree.SpanningTreeEvent.BEFORE_SET_PARENT,
            before
        )
        tree.set_hook(
            spanningtree.SpanningTreeEvent.AFTER_SET_PARENT,
            after
        )

        assert signal['before'] is False
        assert signal['after'] is False

        tree.set_parent(b'parent id bytes')

        assert type(signal['before']) is dict
        assert 'parent_id' in signal['before']
        assert 'parent_data' in signal['before']
        assert 'current_parent_id' in signal['before']
        assert 'current_parent_data' in signal['before']

        assert type(signal['after']) is dict
        assert 'parent_id' in signal['after']
        assert 'parent_data' in signal['after']

    def test_LocalTree_hooks_for_add_child_events(self):
        signal = {
            'before': False,
            'after': False,
        }
        def before(event, data):
            signal['before'] = data
        def after(event, data):
            signal['after'] = data

        tree = spanningtree.LocalTree()
        tree.set_hook(
            spanningtree.SpanningTreeEvent.BEFORE_ADD_CHILD,
            before
        )
        tree.set_hook(
            spanningtree.SpanningTreeEvent.AFTER_ADD_CHILD,
            after
        )

        assert signal['before'] is False
        assert signal['after'] is False

        tree.add_child(b'child id bytes')

        assert type(signal['before']) is dict
        assert 'child_id' in signal['before']
        assert 'child_data' in signal['before']
        assert 'child_ids' in signal['before']
        assert 'all_child_data' in signal['before']

        assert type(signal['after']) is dict
        assert 'child_id' in signal['after']
        assert 'child_ids' in signal['after']
        assert 'child_data' in signal['after']

    def test_LocalTree_hooks_for_remove_child_events(self):
        signal = {
            'before': False,
            'after': False,
        }
        def before(event, data):
            signal['before'] = data
        def after(event, data):
            signal['after'] = data

        tree = spanningtree.LocalTree()
        tree.set_hook(
            spanningtree.SpanningTreeEvent.BEFORE_REMOVE_CHILD,
            before
        )
        tree.set_hook(
            spanningtree.SpanningTreeEvent.AFTER_REMOVE_CHILD,
            after
        )

        assert signal['before'] is False
        assert signal['after'] is False

        tree.remove_child(b'child id bytes')

        assert type(signal['before']) is dict
        assert 'child_id' in signal['before']
        assert 'child_data' in signal['before']
        assert 'child_ids' in signal['before']
        assert 'all_child_data' in signal['before']

        assert type(signal['after']) is dict
        assert 'child_id' in signal['after']
        assert 'child_ids' in signal['after']
        assert 'child_data' in signal['after']

    def test_LocalTree_hooks_for_add_neighbor_events(self):
        signal = {
            'before': False,
            'after': False,
        }
        def before(event, data):
            signal['before'] = data
        def after(event, data):
            signal['after'] = data

        tree = spanningtree.LocalTree()
        tree.set_hook(
            spanningtree.SpanningTreeEvent.BEFORE_ADD_NEIGHBOR,
            before
        )
        tree.set_hook(
            spanningtree.SpanningTreeEvent.AFTER_ADD_NEIGHBOR,
            after
        )

        assert signal['before'] is False
        assert signal['after'] is False

        tree.add_neighbor(b'neighbor id bytes')

        assert type(signal['before']) is dict
        assert 'neighbor_id' in signal['before']
        assert 'neighbor_data' in signal['before']
        assert 'neighbor_ids' in signal['before']
        assert 'all_neighbor_data' in signal['before']

        assert type(signal['after']) is dict
        assert 'neighbor_id' in signal['after']
        assert 'neighbor_ids' in signal['after']
        assert 'neighbor_data' in signal['after']

    def test_LocalTree_hooks_for_remove_neighbor_events(self):
        signal = {
            'before': False,
            'after': False,
        }
        def before(event, data):
            signal['before'] = data
        def after(event, data):
            signal['after'] = data

        tree = spanningtree.LocalTree()
        tree.set_hook(
            spanningtree.SpanningTreeEvent.BEFORE_REMOVE_NEIGHBOR,
            before
        )
        tree.set_hook(
            spanningtree.SpanningTreeEvent.AFTER_REMOVE_NEIGHBOR,
            after
        )

        assert signal['before'] is False
        assert signal['after'] is False

        tree.remove_neighbor(b'neighbor id bytes')

        assert type(signal['before']) is dict
        assert 'neighbor_id' in signal['before']
        assert 'neighbor_data' in signal['before']
        assert 'neighbor_ids' in signal['before']
        assert 'all_neighbor_data' in signal['before']

        assert type(signal['after']) is dict
        assert 'neighbor_id' in signal['after']
        assert 'neighbor_ids' in signal['after']
        assert 'neighbor_data' in signal['after']

    def test_LocalTree_jsonification(self):
        # tree structure
        parent_id = b'parent'
        node_id = b'some node'
        child_ids = [
            b'child0',
            b'child1',
            b'child2',
        ]
        neighbor_ids = [
            b'neighbor0',
            b'neighbor1'
        ]

        tree = spanningtree.LocalTree(node_id=node_id)

        assert tree.parent_id != parent_id
        tree.set_parent(parent_id, {'salt': token_bytes(8).hex()})
        assert tree.parent_id == parent_id

        for cid in child_ids:
            assert cid not in tree.child_ids
            tree.add_child(cid, {'salt': token_bytes(8).hex()})
            assert cid in tree.child_ids

        for nid in neighbor_ids:
            assert nid not in tree.neighbor_ids
            tree.add_neighbor(nid, {'salt': token_bytes(8).hex()})
            assert nid in tree.neighbor_ids

        assert hasattr(tree, 'to_json')
        assert callable(tree.to_json)
        packed = tree.to_json()
        assert type(packed) is str

        assert hasattr(spanningtree.LocalTree, 'from_json')
        assert callable(spanningtree.LocalTree.from_json)
        unpacked = spanningtree.LocalTree.from_json(packed)
        assert type(unpacked) is spanningtree.LocalTree

        assert unpacked.id == tree.id
        assert unpacked.parent_id == tree.parent_id
        assert unpacked.parent_data == tree.parent_data
        assert unpacked.child_ids == tree.child_ids
        assert unpacked.child_data == tree.child_data
        assert unpacked.neighbor_ids == tree.neighbor_ids
        assert unpacked.neighbor_data == tree.neighbor_data


if __name__ == '__main__':
    unittest.main()
