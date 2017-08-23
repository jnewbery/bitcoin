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
        """Main test logic"""

        self.log.info("Compare responses from getinfo RPC and `bitcoin-cli getinfo`")
        cli_get_info = self.nodes[0].cli.getinfo()
        rpc_get_info = self.nodes[0].getinfo()

        assert_equal(cli_get_info, rpc_get_info)

        self.log.info("Compare responses from `bitcoin-cli getinfo` and `bitcoin-cli --getinfo`")
        cli_get_info2 = self.nodes[0].cli(['--getinfo']).help()

        assert_equal(cli_get_info['version'], cli_get_info2['version'])
        assert_equal(cli_get_info['protocolversion'], cli_get_info2['protocolversion'])
        assert_equal(cli_get_info['walletversion'], cli_get_info2['walletversion'])
        assert_equal(cli_get_info['balance'], cli_get_info2['balance'])
        assert_equal(cli_get_info['blocks'], cli_get_info2['blocks'])
        assert_equal(cli_get_info['timeoffset'], cli_get_info2['timeoffset'])
        assert_equal(cli_get_info['connections'], cli_get_info2['connections'])
        assert_equal(cli_get_info['proxy'], cli_get_info2['proxy'])
        assert_equal(cli_get_info['difficulty'], cli_get_info2['difficulty'])
        assert_equal(cli_get_info['testnet'], cli_get_info2['testnet'])
        assert_equal(cli_get_info['walletversion'], cli_get_info2['walletversion'])
        assert_equal(cli_get_info['balance'], cli_get_info2['balance'])
        assert_equal(cli_get_info['keypoololdest'], cli_get_info2['keypoololdest'])
        assert_equal(cli_get_info['keypoolsize'], cli_get_info2['keypoolsize'])
        assert_equal(cli_get_info['unlocked_until'], cli_get_info2['unlocked_until'])
        assert_equal(cli_get_info['paytxfee'], cli_get_info2['paytxfee'])
        assert_equal(cli_get_info['relayfee'], cli_get_info2['relayfee'])

if __name__ == '__main__':
    TestBitcoinCli().main()
