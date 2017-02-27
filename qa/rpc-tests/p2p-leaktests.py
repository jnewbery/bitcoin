#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test message sending before handshake completion.

A node should never send anything other than VERSION/VERACK/REJECT until it's
received a VERACK.

This test connects to a node and sends it a few messages, trying to intice it
into sending us something it shouldn't.
"""

import time

from test_framework.mininode import (NetworkThread,
                                     NodeConn,
                                     NodeConnCB,
                                     wait_until)
from test_framework.primitives import (msg_getaddr,
                                       msg_ping,
                                       msg_verack)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (start_nodes,
                                 p2p_port)

banscore = 10

# Node that never sends a version. This one just sits idle and hopes to receive
# any message (it shouldn't!)
class CLazyNode(NodeConnCB):
    def __init__(self):
        super().__init__()
        self.unexpected_msg = False

    def bad_message(self, message):
        self.unexpected_msg = True
        print("should not have received message: %s" % message.command)

    def on_version(self, conn, message): self.bad_message(message)
    def on_verack(self, conn, message): self.bad_message(message)
    def on_reject(self, conn, message): self.bad_message(message)
    def on_inv(self, conn, message): self.bad_message(message)
    def on_addr(self, conn, message): self.bad_message(message)
    def on_alert(self, conn, message): self.bad_message(message)
    def on_getdata(self, conn, message): self.bad_message(message)
    def on_getblocks(self, conn, message): self.bad_message(message)
    def on_tx(self, conn, message): self.bad_message(message)
    def on_block(self, conn, message): self.bad_message(message)
    def on_getaddr(self, conn, message): self.bad_message(message)
    def on_headers(self, conn, message): self.bad_message(message)
    def on_getheaders(self, conn, message): self.bad_message(message)
    def on_ping(self, conn, message): self.bad_message(message)
    def on_mempool(self, conn): self.bad_message(message)
    def on_pong(self, conn, message): self.bad_message(message)
    def on_feefilter(self, conn, message): self.bad_message(message)
    def on_sendheaders(self, conn, message): self.bad_message(message)
    def on_sendcmpct(self, conn, message): self.bad_message(message)
    def on_cmpctblock(self, conn, message): self.bad_message(message)
    def on_getblocktxn(self, conn, message): self.bad_message(message)
    def on_blocktxn(self, conn, message): self.bad_message(message)

# Node that never sends a version. We'll use this to send a bunch of messages
# anyway, and eventually get disconnected.
class CNodeNoVersionBan(CLazyNode):

    # send a bunch of veracks without sending a message. This should get us disconnected.
    # NOTE: implementation-specific check here. Remove if bitcoind ban behavior changes
    def on_open(self, conn):
        self.connected = True
        for i in range(banscore):
            self.send_message(msg_verack())

    def on_reject(self, conn, message): pass

# Node that sends a version but not a verack.
class CNodeNoVerackIdle(CLazyNode):

    def on_reject(self, conn, message): pass
    def on_verack(self, conn, message): pass
    # When version is received, don't reply with a verack. Instead, see if the
    # node will give us a message that it shouldn't. This is not an exhaustive
    # list!
    def on_version(self, conn, message):
        conn.send_message(msg_ping())
        conn.send_message(msg_getaddr())

class P2PLeakTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
    def setup_network(self):
        extra_args = [['-debug', '-banscore='+str(banscore)]
                      for i in range(self.num_nodes)]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args)

    def run_test(self):
        no_version_bannode = CNodeNoVersionBan()
        no_version_idlenode = CLazyNode()
        no_verack_idlenode = CNodeNoVerackIdle()

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], no_version_bannode, send_version=False))
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], no_version_idlenode, send_version=False))
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], no_verack_idlenode))
        no_version_bannode.add_connection(connections[0])
        no_version_idlenode.add_connection(connections[1])
        no_verack_idlenode.add_connection(connections[2])

        NetworkThread().start()  # Start up network handling in another thread

        assert wait_until(lambda: no_version_bannode.connected, timeout=60)
        assert wait_until(lambda: no_version_idlenode.connected, timeout=60)
        assert wait_until(lambda: no_verack_idlenode.last_message.get("version"), timeout=60)

        # Mine a block and make sure that it's not sent to the connected nodes
        self.nodes[0].generate(1)

        #Give the node enough time to possibly leak out a message
        time.sleep(5)

        #This node should have been banned
        assert not no_version_bannode.connected

        [conn.disconnect_node() for conn in connections]

        # Make sure no unexpected messages came in
        assert not no_version_bannode.unexpected_msg
        assert not no_version_idlenode.unexpected_msg
        assert not no_verack_idlenode.unexpected_msg

if __name__ == '__main__':
    P2PLeakTest().main()
