#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block processing."""
import time

from test_framework.blocktools import *
from test_framework.key import CECKey
from test_framework.script import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class PreviousSpendableOutput():
    def __init__(self, tx=CTransaction(), n=-1):
        self.tx = tx
        self.n = n  # the output we're spending

class LargeReorgTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.block_heights = {}
        self.coinbase_key = CECKey()
        self.coinbase_key.set_secretbytes(b"horsebattery")
        self.coinbase_pubkey = self.coinbase_key.get_pubkey()
        self.tip = None
        self.blocks = {}

    def setup_network(self):
        self.nodes = [self.start_node(0, extra_args=['-whitelist=127.0.0.1'])]

    def run_test(self):
        # Add p2p connection to node0
        node = self.nodes[0]  # convenience reference to the node
        node.add_p2p_connections()

        NetworkThread().start()  # Start up network handling in another thread
        node.p2p.wait_for_verack()

        self.genesis_hash = int(self.nodes[0].getbestblockhash(), 16)
        self.block_heights[self.genesis_hash] = 0
        self.spendable_outputs = []

        # Create a new block
        b0 = self.next_block(0)
        self.sync_blocks([b0])

        self.save_spendable_output()

        # Allow the block to mature
        blocks = []
        for i in range(99):
            blocks.append(self.next_block(5000 + i))
            self.save_spendable_output()
        self.sync_blocks(blocks, True)

        pre_fork_tip = 5000 + i

        self.move_tip(pre_fork_tip)
        # collect spendable outputs now to avoid cluttering the code later on
        # out = []
        # for i in range(33):
        #     out.append(self.get_spendable_output())

        #  Test re-org of a week's worth of blocks (1088 blocks)
        #  This test takes a minute or two and can be accomplished in memory
        #
        LARGE_REORG_SIZE = 1088
        spend = self.get_spendable_output()
        blocks = []
        for i in range(1, LARGE_REORG_SIZE + 1):
            b = self.next_block(i, spend)
            tx = CTransaction()
            script_length = MAX_BLOCK_BASE_SIZE - len(b.serialize()) - 69
            script_output = CScript([b'\x00' * script_length])
            tx.vout.append(CTxOut(0, script_output))
            tx.vin.append(CTxIn(COutPoint(b.vtx[1].sha256, 0)))
            b = self.update_block(i, [tx])
            assert_equal(len(b.serialize()), MAX_BLOCK_BASE_SIZE)
            blocks.append(b)
            self.save_spendable_output()
            spend = self.get_spendable_output()

        self.sync_blocks(blocks, True)
        chain1_tip = i

        # now create alt chain of same length
        self.move_tip(pre_fork_tip)
        blocks2 = []
        for i in range(1, LARGE_REORG_SIZE + 1):
            blocks2.append(self.next_block("alt"+str(i)))
        self.sync_blocks(blocks2, False)

        # extend alt chain to trigger re-org
        block = self.next_block("alt" + str(chain1_tip + 1))
        self.sync_blocks([block], True)

        # ... and re-org back to the first chain
        self.move_tip(chain1_tip)
        block = self.next_block(chain1_tip + 1)
        self.sync_blocks([block], False)
        block = self.next_block(chain1_tip + 2)
        self.sync_blocks([block], True)

    # Helper methods
    ################

    def add_transactions_to_block(self, block, tx_list):
        [tx.rehash() for tx in tx_list]
        block.vtx.extend(tx_list)

    # sign a transaction, using the key we know about
    # this signs input 0 in tx, which is assumed to be spending output n in spend_tx
    def sign_tx(self, tx, spend_tx, n):
        scriptPubKey = bytearray(spend_tx.vout[n].scriptPubKey)
        if (scriptPubKey[0] == OP_TRUE):  # an anyone-can-spend
            tx.vin[0].scriptSig = CScript()
            return
        (sighash, err) = SignatureHash(spend_tx.vout[n].scriptPubKey, tx, 0, SIGHASH_ALL)
        tx.vin[0].scriptSig = CScript([self.coinbase_key.sign(sighash) + bytes(bytearray([SIGHASH_ALL]))])

    def next_block(self, number, spend=None, additional_coinbase_value=0, script=CScript([OP_TRUE]), solve=True):
        if self.tip is None:
            base_block_hash = self.genesis_hash
            block_time = int(time.time()) + 1
        else:
            base_block_hash = self.tip.sha256
            block_time = self.tip.nTime + 1
        # First create the coinbase
        height = self.block_heights[base_block_hash] + 1
        coinbase = create_coinbase(height, self.coinbase_pubkey)
        coinbase.vout[0].nValue += additional_coinbase_value
        coinbase.rehash()
        if spend is None:
            block = create_block(base_block_hash, coinbase, block_time)
        else:
            coinbase.vout[0].nValue += spend.tx.vout[spend.n].nValue - 1  # all but one satoshi to fees
            coinbase.rehash()
            block = create_block(base_block_hash, coinbase, block_time)
            tx = create_transaction(spend.tx, spend.n, b"", 1, script)  # spend 1 satoshi
            self.sign_tx(tx, spend.tx, spend.n)
            self.add_transactions_to_block(block, [tx])
            block.hashMerkleRoot = block.calc_merkle_root()
        if solve:
            block.solve()
        self.tip = block
        self.block_heights[block.sha256] = height
        assert number not in self.blocks
        self.blocks[number] = block
        return block

    # save the current tip so it can be spent by a later block
    def save_spendable_output(self):
        self.spendable_outputs.append(self.tip)

    # get an output that we previously marked as spendable
    def get_spendable_output(self):
        return PreviousSpendableOutput(self.spendable_outputs.pop(0).vtx[0], 0)

    # move the tip back to a previous block
    def move_tip(self, number):
        self.tip = self.blocks[number]

    # adds transactions to the block and updates state
    def update_block(self, block_number, new_transactions):
        block = self.blocks[block_number]
        self.add_transactions_to_block(block, new_transactions)
        old_sha256 = block.sha256
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        # Update the internal state just like in next_block
        self.tip = block
        if block.sha256 != old_sha256:
            self.block_heights[block.sha256] = self.block_heights[old_sha256]
            del self.block_heights[old_sha256]
        self.blocks[block_number] = block
        return block

    def sync_blocks(self, blocks, success=True, reject_code=None, reject_reason=None):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        if reject_code is not None:
            self.nodes[0].p2p.reject_code = reject_code
        if reject_reason is not None:
            self.nodes[0].p2p.reject_reason = reject_reason
        for block in blocks:
            self.nodes[0].send_message(msg_block(block))
        self.nodes[0].p2p.sync_with_ping()
        if success:
            assert_equal(self.nodes[0].getbestblockhash(), blocks[-1].hash)
        else:
            assert self.nodes[0].getbestblockhash() != blocks[-1].hash

if __name__ == '__main__':
    LargeReorgTest().main()
