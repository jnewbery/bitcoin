#!/usr/bin/env python3
# Copyright (c) 2014 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a node can resync to the main chain after running invalidateblock

Blocks are generated on node0, and then invalidated on both nodes. Syncing the
alternate chain validates that nodes can resync after running invalidateblock."""
from test_framework.test_framework import BitcoinTestFramework

GENERATION_ADDR1 = 'mjTkW3DjgyZck4KbiRusZsqTgaYTxdSz6z'
GENERATION_ADDR2 = 'msX6jQXvxiNhx3Q62PKeLPrhrqZQdSimTg'

class InvalidateBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def run_test(self):
        node = self.nodes[0]

        block_count = node.getblockcount()

        self.log.info("Generate blocks")
        block_hashes = node.generatetoaddress(18, GENERATION_ADDR1)
        assert node.getblockcount() == block_count + 18
        self.sync_all()

        self.log.info("Invalidate block")
        node.invalidateblock(block_hashes[0])
        self.nodes[1].invalidateblock(block_hashes[0])
        assert node.getblockcount() == block_count

        self.log.info("Generate alternate chain")
        # Generate to a different address to ensure that the coinbase
        # transaction (and therefore also the block hash) is different.
        node.generatetoaddress(17, GENERATION_ADDR2)
        self.sync_all()

        self.log.info("Verify that node syncs to tip")
        assert node.getblockcount() == block_count + 17

if __name__ == '__main__':
    InvalidateBlockTest().main()
