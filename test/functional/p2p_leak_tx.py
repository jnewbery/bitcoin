#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we don't leak txs to inbound peers that we haven't yet announced to

setup:
- Start 2 nodes and connect them. Node 0 is the test node.
- Open a P2P connection to node 0.

test:
- Create a transaction on node 0.
- Wait until the transaction is propogated to node 1.
- send a getdata for the tx to node 0 over the inbound connection.
- because the inv propogation is random poisson distributed, either:
    - the tx was already announced over the inbound connection and node 0 will respond to the getdata with a tx.
    - the tx was not yet announced over the inbound connection and node 0 will reply to the getdata with a notfound. End the test.

Repeat the test up to 100 times to catch the condition where the tx was propogated to the outbound node but note the inbound node."""
from test_framework.messages import msg_getdata, CInv
from test_framework.mininode import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    wait_until,
)

class P2PNode(P2PDataStore):
    def on_inv(self, msg):
        pass

class P2PLeakTxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        gen_node = self.nodes[0]  # The block and tx generating node
        gen_node.generate(1)
        self.sync_all()

        inbound_peer = self.nodes[0].add_p2p_connection(P2PNode())  # An "attacking" inbound peer

        MAX_REPEATS = 100
        self.log.info("Running test up to {} times.".format(MAX_REPEATS))
        for i in range(MAX_REPEATS):
            self.log.info('Run repeat {}'.format(i + 1))
            txid = gen_node.sendtoaddress(gen_node.getnewaddress(), 0.01)

            wait_until(lambda: txid in self.nodes[1].getrawmempool(), timeout=10)

            want_tx = msg_getdata()
            want_tx.inv.append(CInv(t=1, h=int(txid, 16)))
            inbound_peer.last_message.pop('notfound', None)
            inbound_peer.send_message(want_tx)
            inbound_peer.sync_with_ping()

            if inbound_peer.last_message.get('notfound'):
                self.log.debug('tx {} was announced to outbound peer but not to us.'.format(txid))
                self.log.debug("node has responded with a notfound message. End test.")
                assert_equal(inbound_peer.last_message['notfound'].vec[0].hash, int(txid, 16))
                inbound_peer.last_message.pop('notfound')
                break
            else:
                self.log.debug('tx {} was already announced to us.'.format(txid))
                assert int(txid, 16) in [inv.hash for inv in inbound_peer.last_message['inv'].inv]

if __name__ == '__main__':
    P2PLeakTxTest().main()
