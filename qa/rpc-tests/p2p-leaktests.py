#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

BANSCORE=10

class CLazyNode(NodeConnCB):
    def __init__(self):
        super().__init__()
        self.unexpected_messages = []

    def add_connection(self, conn):
        self.connection = conn

    def deliver(self, conn, message):
        # print("received " + message.command.decode('ascii') + " on " + self.__class__.__name__)
        if message.command not in self.accepted_messages:
            self.unexpected_messages += message.command.decode('ascii')

# Node that never sends a version. We'll use this to send a bunch of messages
# anyway, and eventually get disconnected.
class CNodeNoVersionBan(CLazyNode):
    def __init__(self):
        super().__init__()
        # This node shouldn't receive any messages
        self.accepted_messages = []

# Node that never sends a version. This one just sits idle and hopes to receive
# any message (it shouldn't!)
class CNodeNoVersionIdle(CLazyNode):
    def __init__(self):
        super().__init__()
        # This node shouldn't receive any messages
        self.accepted_messages = []

# Node that sends a version but not a verack.
class CNodeNoVerackIdle(CLazyNode):
    def __init__(self):
        super().__init__()
        # It's ok for to receive version and verack messages
        self.accepted_messages = [b'version', b'verack']

    def deliver(self, conn, message):
        if message.command == b'version':
            # with mininode_lock:
                # When version is received, don't reply with a verack. Instead, see if the
                # node will give us a message that it shouldn't. This is not an exhaustive
                # list!
            conn.send_message(msg_ping())
            conn.send_message(msg_getaddr())

        super().deliver(conn, message)

class P2PLeakTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [['-debug', '-banscore='+str(BANSCORE)]])

    def run_test(self):
        no_version_bannode = CNodeNoVersionBan()
        no_version_idlenode = CNodeNoVersionIdle()
        no_verack_idlenode = CNodeNoVerackIdle()

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], no_version_bannode, send_version=False))
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], no_version_idlenode, send_version=False))
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], no_verack_idlenode))
        no_version_bannode.add_connection(connections[0])
        no_version_idlenode.add_connection(connections[1])
        no_verack_idlenode.add_connection(connections[2])

        # Start up network handling in another thread
        NetworkThread().start()

        # send a bunch of veracks without sending a version message. This should get us disconnected.
        # NOTE: implementation-specific check here. Remove if bitcoind ban behavior changes
        for i in range(BANSCORE):
            no_version_bannode.connection.send_message(msg_verack())

        #Give the node enough time to possibly leak out a message
        time.sleep(5)

        # Check that the node hasn't send any unexpected messages
        assert(not no_version_bannode.unexpected_messages)
        assert(not no_version_idlenode.unexpected_messages)
        assert(not no_verack_idlenode.unexpected_messages)

        # Disconnect all peers
        [conn.disconnect_node() for conn in connections]

if __name__ == '__main__':
    P2PLeakTest().main()
