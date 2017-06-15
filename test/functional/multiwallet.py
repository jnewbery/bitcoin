#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test multiwallet

Verify that a bitcoind node can load multiple wallet files
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class Multiwallet(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.extra_args = [["-wallet=wallet0.dat"]]

    def run_test(self):
        # Refill the keypool so getwalletinfo shows the keypoololdest variable
        # doesn't change between getwalletinfo calls
        self.nodes[0].keypoolrefill()
        wallet0_info = self.nodes[0].getwalletinfo()[0]

        # stop-start the node with a new wallet
        self.stop_nodes()
        self.nodes[0] = self.start_node(0, self.options.tmpdir, ["-wallet=wallet1.dat"])
        self.nodes[0].keypoolrefill()
        wallet1_info = self.nodes[0].getwalletinfo()[0]

        # Stop the node and load both wallets
        self.stop_nodes()
        self.nodes[0] = self.start_node(0, self.options.tmpdir, ["-wallet=wallet0.dat", "-wallet=wallet1.dat"])
        wallets_info = self.nodes[0].getwalletinfo()

        # Assert that node0 has loaded both wallets correctly
        assert_equal(wallets_info[0], wallet0_info)
        assert_equal(wallets_info[1], wallet1_info)

if __name__ == '__main__':
    Multiwallet().main()
