#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet getbalance RPC methods."""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

class WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def create_transactions(self, node, address, amt, fees):
        # Create and sign raw transactions from node to address for amt.
        # Creates a transaction for each fee and returns an array
        # of the raw transactions.
        utxos = node.listunspent(0)

        # Create transactions
        inputs = []
        ins_total = 0
        for utxo in utxos:
            inputs.append({"txid": utxo["txid"], "vout": utxo["vout"]})
            ins_total += utxo['amount']
            if ins_total > amt:
                break

        txs = []
        for fee in fees:
            outputs = {address: amt, node.getrawchangeaddress(): ins_total - amt - fee}
            raw_tx = node.createrawtransaction(inputs, outputs, 0, True)
            raw_tx = node.signrawtransactionwithwallet(raw_tx)
            txs.append(raw_tx)

        return txs

    def run_test(self):
        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)

        self.log.info("Mining blocks...")

        self.nodes[0].generate(1)
        self.sync_all()
        self.nodes[1].generate(1)
        self.nodes[1].generatetoaddress(100, 'mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ')  # random address
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), 50)
        assert_equal(self.nodes[1].getbalance(), 50)

        # Test getbalance with different arguments
        assert_equal(self.nodes[0].getbalance("*"), 50)
        assert_equal(self.nodes[0].getbalance("*", 1), 50)
        assert_equal(self.nodes[0].getbalance("*", 1, True), 50)
        assert_equal(self.nodes[0].getbalance(minconf=1), 50)

        # Send 40 BTC from 0 to 1 and 60 BTC from 1 to 0.
        txs = self.create_transactions(self.nodes[0], self.nodes[1].getnewaddress(), 40, [Decimal('0.01')])
        self.nodes[0].sendrawtransaction(txs[0]['hex'])
        self.sync_all()
        txs = self.create_transactions(self.nodes[1], self.nodes[0].getnewaddress(), 60, [Decimal('0.01'), Decimal('0.02')])
        self.nodes[1].sendrawtransaction(txs[0]['hex'])
        self.sync_all()

        # First argument of getbalance is include_untrusted and must be absent or set to "*"
        assert_raises_rpc_error(-8, "include_untrusted must be absent or set to \"*\"", self.nodes[1].getbalance, "")

        # Test getbalance with different arguments

        # getbalance without any arguments includes unconfirmed transactions, but not untrusted transactions
        assert_equal(self.nodes[0].getbalance(), Decimal('9.99'))  # change from node 0's send
        assert_equal(self.nodes[1].getbalance(), Decimal('29.99'))  # change from node 1's send
        # Same with minconf=0
        assert_equal(self.nodes[0].getbalance(minconf=0), Decimal('9.99'))
        assert_equal(self.nodes[1].getbalance(minconf=0), Decimal('29.99'))
        # getbalance with include_untrusted and a minconf will not show unconfirmed transactions
        assert_equal(self.nodes[0].getbalance(minconf=1), Decimal('50'))
        assert_equal(self.nodes[1].getbalance(minconf=1), Decimal('50'))
        # getbalance with include_untrusted includes all unconfirmed and untrusted transactions
        assert_equal(self.nodes[0].getbalance("*"), Decimal('119.99'))  # node 1's send plus change from node 0's send
        assert_equal(self.nodes[1].getbalance("*"), Decimal('79.99'))  # change from node 1's send
        # Same with minconf=0
        assert_equal(self.nodes[0].getbalance("*"), Decimal('119.99'))
        assert_equal(self.nodes[1].getbalance("*"), Decimal('79.99'))
        # getbalance with include_untrusted and a minconf will not show unconfirmed transactions
        assert_equal(self.nodes[0].getbalance("*", 1), Decimal('50'))
        assert_equal(self.nodes[1].getbalance("*", 1), Decimal('50'))

        # Node 1 bumps the transaction fee and resends
        self.nodes[1].sendrawtransaction(txs[1]['hex'])
        self.sync_all()

        # getbalance with include_untrusted will double-count bumped transactions
        assert_equal(self.nodes[0].getbalance("*"), Decimal('179.99'))
        assert_equal(self.nodes[1].getbalance("*"), Decimal('59.97'))

        self.nodes[1].generatetoaddress(1, 'mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ')  # random address
        self.sync_all()

        # balances are correct after the transactions are confirmed
        assert_equal(self.nodes[0].getbalance("*"), Decimal('69.99'))  # node 1's send plus change from node 0's send
        assert_equal(self.nodes[1].getbalance("*"), Decimal('29.98'))  # change from node 0's send

        # Send total balance away from node 1
        txs = self.create_transactions(self.nodes[1], self.nodes[0].getnewaddress(), Decimal('29.97'), [Decimal('0.01')])
        self.nodes[1].sendrawtransaction(txs[0]['hex'])
        self.nodes[1].generatetoaddress(2, 'mneYUmWYsuk7kySiURxCi3AGxrAqZxLgPZ')  # random address
        self.sync_all()

        # getbalance with minconf=3 should still show the old balance (since the send does not have 3 confirmations)
        assert_equal(self.nodes[1].getbalance(minconf=3), Decimal('29.98'))

        # getbalance with minconf=2 will show the new balance.
        assert_equal(self.nodes[1].getbalance(minconf=2), Decimal('0'))

if __name__ == '__main__':
    WalletTest().main()
