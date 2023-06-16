# Murmurs

This library provides p2p networking with gossip and several spanning tree-based
protocols: PIE, VOUTE, and SpeedyMurmurs. To address vulnerabilities to spoofing
and Sybil attacks, a system called proof-of-luck is included for root election.

## Protocol/Algorithm Overview

### Gossip

The basic idea of gossip is that each node that receives a message forwards it
to at least 2 peers, leading to a message being transmitted to every node in the
network quickly and efficiently without using broadcast/flooding. In practice,
there are two modes with configurable behavior:

- Push: when a node receives a new message, it stores and forwards to peers
- Pull: periodically, a node requests new messages from peers

These two modes can also be combined by using push as the normal mode and
periodic pulls for synchronization. As an optimization, peers can exchange
message headers/digests instead of the full messages, and they can exchange
checksums of message headers as a potential further optimization.

In this implementation, message headers include a timestamp, nonce, and content
hash, and they use proof-of-work as an antispam feature. Messages that are too
old are ignored by default. Upon connection, peers synchronize by exchanging
message header hashes, then request any missing messages; thereafter, they store
and forward. A pub/sub system using topics is also included. Gossip forms the
basic layer used to bootstrap the spanning tree construction for SpeedyMurmurs.

### Spanning Tree

In 1985, Radia Perlman published An Algorithm for Distributed Computation of a
Spanning Tree in an Extended LAN. This algorithm is the basis for many protocols
designed to map a network topology, and its essence was encapsulated in the
following poem ("Algorhyme"):

```
I think that I shall never see
A graph more lovely than a tree.

A tree whose crucial property
Is loop-free connectivity.

A tree which must be sure to span
So packets can reach every LAN.

First the Root must be selected.
By ID it is elected.

Least cost paths from Root are traced.
In the tree these paths are placed.

A mesh is made by folks like me
Then bridges find a spanning tree.
```

The general idea is that each node uses its public key as its ID, and the node
with an ID that has the lowest distance from a target byte string becomes the
logical root. This logical root node has an address of all zeroes and can assign
an address to a peer by setting any of the null bytes in its address to a non-
null value. These child nodes can then assign addresses to their children by
setting any null byte less significant than their least significant non-null
byte, and this step generalizes until the address space is exhausted. This
system uses 32-byte (256 bits) addresses, which is twice the address space of
IPv6.

For example, borrowing IPv6 compact address notation:

- root = ::
    - node_1 = 01::
    - node_2 = 02::
        - node_2_1 = 02:01::
        - node_2_2 = 02:02::
        - node_2_3 = 02:03::
            - node_2_3_255 = 02:03:ff::
    - node_0_255 = 00:ff::
        - node_0_255_1 = 0:ff:01::

The root thus has a total of 2^8 * 32 = 8192 assignable addresses available for
child nodes. Nodes assigned an address with only the first byte set have a total
of 2^8 * 31 = 7936 assignable addresses available for child nodes. In general,
the number of assignable addresses available to a node is 2^8 * (32 - lsnb),
where lsnb is the index of the least significant non-null byte of the assigned
address (with index of 0 meaning the root with no non-null bytes).

This scheme gives child nodes fewer assignable addresses the further they are
from the root in the spanning tree, but it also allows any node at any place in
the tree to assign an address to a child that will not participate in routing
and thus will not need the ability to assign addresses. Addresses in this scheme
embed the network topology into the addresses themselves.

The election of the root is deterministic and replicable, and any node that
enters the network and has a better ID can displace the current root once its
term expires. Address assignments are signed by the assigning parent node, and a
chain of signatures stretching back to the root verifies each link in the tree.

### PIE: Practical Isometric Embedding Protocol

PIE was introduced in 2013 by Herzen et al. and is a protocol that uses multiple
spanning trees as the basis for embedding a graph into a coordinate system, and
then uses the coordinates as the basis for greedy routing. Their paper showed
that the scheme generalizes to any graph, routes with a 100% success rate, can
accomodate link costs, and generally chooses an optimal or near-optimal route
path, all while using only local peer communications and local routing state
information (i.e. the coordinates of peers).

There are three primary algorithms in PIE: the the tree constructor/maintainer,
called tree_maintainer, the coordinate mapper, called coordinates_maintainer,
and the routing algorithm using the distance metric. Overviews and pseudocode
for these are given below. Note that all of these algorithms work with local
state.

For high resillience, there is one tree that spans the whole graph. For improved
routing efficiency, there are a number of localized trees that span sections of
the graph.

@todo explain local trees

#### tree_maintainer

The tree maintainer handles building and maintaining spanning trees.

@todo

#### coordinates_maintainer

@todo

#### Distance metric and routing

@todo

### VOUTE

VOUTE

Routing is accomplished by comparing the destination address to the addresses of
peers and forwarding to the peer with the smallest distance from the destination.
There are two distance metrics defined:

### SpeedyMurmurs

SpeedyMurmurs is a collection of algorithms used for routing payments in a F2F
overlay network using a greedy embedding based upon a spanning tree setup that
expands VOUTE with handling of weighted links.

## Status

- [ ] Start
- [ ] Finish
- [ ] Documentation

## Usage

### Installation

### Testing

## License

ISC License

Copyleft (c) 2023 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

Exceptions: this permission is not granted to Alphabet/Google, Amazon,
Apple, Microsoft, Netflix, Meta/Facebook, Twitter, or Disney; nor is
permission granted to any company that contracts to supply weapons or
logistics to any national military; nor is permission granted to any
national government or governmental agency; nor is permission granted to
any employees, associates, or affiliates of these designated entities.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
