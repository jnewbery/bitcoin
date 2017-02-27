#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test node responses to invalid transactions.

In this test we connect to one node over p2p and test tx requests.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import *
from test_framework.util import assert_equal, p2p_port
from test_framework.mininode import SingleNodeConnCB, RejectResult
import time

class TestNode(SingleNodeConnCB):

    def __init__(self):
        super().__init__()
        self.connection = None
        self.bestblockhash = None
        self.lastInv = []
        self.block_reject_map = {}
        self.tx_reject_map = {}

    def on_headers(self, conn, message):
        if message.headers:
            best_header = message.headers[-1]
            best_header.calc_sha256()
            self.bestblockhash = best_header.sha256

    def on_inv(self, conn, message):
        self.lastInv = [x.hash for x in message.inv]

    def on_reject(self, conn, message):
        if message.message == b'tx':
            self.tx_reject_map[message.data] = RejectResult(message.code, message.reason)
        if message.message == b'block':
            self.block_reject_map[message.data] = RejectResult(message.code, message.reason)

class InvalidTxRequestTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split = False):
        self.nodes = self.setup_nodes()

    def run_test(self):

        test_node = TestNode()
        test_node.add_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], test_node))

        NetworkThread().start() # Start up network handling in another thread
        test_node.wait_for_verack()

        tip = int("0x" + self.nodes[0].getbestblockhash(), 0)
        block_time = int(time.time()) + 1

        # self.log.info("Create a new block with an anyone-can-spend coinbase.")

        block = create_block(tip, create_coinbase(1), block_time)
        block_time += 1
        block.solve()
        # Save the coinbase for later
        block1 = block
        # tip = block.sha256
        # height += 1
        test_node.connection.send_message(msg_block(block))

        # Send getheaders to verify that the tip is as expected.
        test_node.send_and_ping(msg_getheaders())

        assert_equal(test_node.bestblockhash, tip)

        # self.log.info("Mature the block so we can spend the coinbase.")

        test_node.generate(100)
        # for i in range(100):
        #     block = create_block(tip, create_coinbase(height), block_time)
        #     block.solve()
        #     tip = block.sha256
        #     block_time += 1
        #     test_node[0].send_message(msg_block(block))
        #     height += 1

        # # Send getheaders to verify that the tip is as expected.
        # test_node.connection.send_getheaders()
        # test_node.connection.sync_with_ping()

        # assert_equal(test_node.bestblockhash, tip)

        # b'\x64' is OP_NOTIF
        # Transaction will be rejected with code 16 (REJECT_INVALID)
        tx1 = create_transaction(self.block1.vtx[0], 0, b'\x64', 50 * COIN - 12000)

        test_node.connection.send_message(msg_tx(tx1))
        assert txhash in test_node.tx_reject_map
        assert_equal(outcome, test_node.tx_reject_map[txhash])

        # TODO: test further transactions...

if __name__ == '__main__':
    InvalidTxRequestTest().main()
