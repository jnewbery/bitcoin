#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoin-cli"""
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal

class TestBitcoinCli(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_nodes(self):
        # Try to import simplejson. Skip this test if the import fails.
        try:
            import simplejson
            simplejson.dumps("suppress linter warning")  # suppresses linter warning about simplejson being unused
        except ImportError:
            raise SkipTest("simplejson module not available.")
        super().setup_nodes()

    def run_test(self):
        """Main test logic"""

        self.log.info("Compare responses from getinfo RPC and `bitcoin-cli getinfo`")
        cli_get_info = self.nodes[0].cli.getinfo()
        rpc_get_info = self.nodes[0].getinfo()

        assert_equal(cli_get_info, rpc_get_info)

if __name__ == '__main__':
    TestBitcoinCli().main()
