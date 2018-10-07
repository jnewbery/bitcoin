#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that it could not start two bitcoind in the same datadir"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

import os

def get_node_output(*, node, ret_code_expected):
    ret_code = node.process.wait(timeout=5)
    assert_equal(ret_code, ret_code_expected)
    node.stdout.seek(0)
    node.stderr.seek(0)
    out = node.stdout.read()
    err = node.stderr.read()
    node.stdout.close()
    node.stderr.close()

    # Clean up TestNode state
    node.running = False
    node.process = None
    node.rpc_connected = False
    node.rpc = None

    return out, err

class FilelockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def run_test(self):
        self.nodes[1].stop()
        self.log.info("Using datadir {}".format(self.nodes[0].datadir))
        self.nodes[1].start(['-datadir={}'.format(self.nodes[0].datadir), '-noserver'])
        _, output = get_node_output(node=self.nodes[1], ret_code_expected=1)
        assert(b'Error: Cannot obtain a lock on data directory %b. Bitcoin Core is probably already running.' % os.path.join(self.nodes[0].datadir, 'regtest').encode('utf-8') in output)


if __name__ == '__main__':
    FilelockTest().main()
