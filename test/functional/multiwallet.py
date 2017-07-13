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
        wallet0_name = self.nodes[0].getwalletinfo()["walletname"]

        # stop-start the node with a new wallet
        self.stop_nodes()
        self.nodes[0] = self.start_node(0, self.options.tmpdir, ["-wallet=wallet1.dat"])
        wallet1_name = self.nodes[0].getwalletinfo()["walletname"]

        # Stop the node and load both wallets
        self.stop_nodes()
        self.nodes[0] = self.start_node(0, self.options.tmpdir, ["-wallet=wallet0.dat", "-wallet=wallet1.dat"])

        # Assert that node0 has loaded both wallets correctly
        assert_equal(self.nodes[0].listwallets(), [wallet0_name, wallet1_name])

        # Check that we can access either wallet using endpoints
        w0 = self.nodes[0] / "v1/wallet/wallet0.dat"
        w1 = self.nodes[0] / "v1/wallet/wallet1.dat"
        assert_equal(w0.getwalletinfo()["walletname"], wallet0_name)
        assert_equal(w1.getwalletinfo()["walletname"], wallet1_name)

if __name__ == '__main__':
    Multiwallet().main()
