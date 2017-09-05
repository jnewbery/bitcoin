#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoin-cli"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class TestBitcoinCli(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):

        self.log.info("Compare responses from gewallettinfo RPC and `bitcoin-cli getwalletinfo`")
        assert_equal(self.nodes[0].cli.getwalletinfo(), self.nodes[0].getwalletinfo())

        self.log.info("Compare responses from getblockchaininfo RPC and `bitcoin-cli getblockchaininfo`")
        assert_equal(self.nodes[0].cli.getblockchaininfo(), self.nodes[0].getblockchaininfo())

        self.log.info("Compare responses from getmininginfo RPC and `bitcoin-cli getmininginfo`")
        assert_equal(self.nodes[0].cli.getmininginfo(), self.nodes[0].getmininginfo())

        self.log.info("Compare responses from getnetworkinfo RPC and `bitcoin-cli getnetworkinfo`")
        assert_equal(self.nodes[0].cli.getnetworkinfo(), self.nodes[0].getnetworkinfo())

if __name__ == '__main__':
    TestBitcoinCli().main()
