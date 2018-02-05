#!/usr/bin/env python3
# Copyright (c) 2016-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test NULLDUMMY softfork.

Connect to a single node.
Generate 101 blocks (save the first coinbase for later).
[Policy/Consensus] Check that the NULLDUMMY rules are enforced in mempool policy and block consensus.
"""
from io import BytesIO
import time

from test_framework.blocktools import create_coinbase, create_block, add_witness_commitment
from test_framework.script import CScript, CTransaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, bytes_to_hex_str, hex_str_to_bytes

NULLDUMMY_ERROR = "64: non-mandatory-script-verify-flag (Dummy CHECKMULTISIG argument must be zero)"

def add_dummy(tx):
    """Add a non-nulldummy element to the TxIn scriptSig"""
    script_sig = CScript(tx.vin[0].scriptSig)
    newscript = []
    for i in script_sig:
        if (len(newscript) == 0):
            assert_equal(len(i), 0)
            newscript.append(b'\x51')
        else:
            newscript.append(i)
    tx.vin[0].scriptSig = CScript(newscript)
    tx.rehash()

def create_transaction(node, txid, to_address, amount):
    inputs = [{"txid": txid, "vout": 0}]
    outputs = {to_address: amount}
    rawtx = node.createrawtransaction(inputs, outputs)
    signresult = node.signrawtransaction(rawtx)
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(signresult['hex']))
    tx.deserialize(f)
    return tx

class NULLDUMMYTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=127.0.0.1', '-walletprematurewitness', '-addresstype=legacy', "-deprecatedrpc=addwitnessaddress"]]

    def run_test(self):
        address = self.nodes[0].getnewaddress()
        ms_address = self.nodes[0].addmultisigaddress(1, [address])['address']
        wit_address = self.nodes[0].addwitnessaddress(address)
        wit_ms_address = self.nodes[0].addmultisigaddress(1, [address], '', 'p2sh-segwit')['address']

        coinbase_blocks = self.nodes[0].generatetoaddress(1, ms_address)
        coinbase_blocks += (self.nodes[0].generatetoaddress(1, wit_ms_address))
        coinbase_txid = []
        for i in coinbase_blocks:
            coinbase_txid.append(self.nodes[0].getblock(i)['tx'][0])

        # Mataure the coinbase transactions
        self.nodes[0].generate(100)
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        self.lastblockheight = 102
        self.lastblocktime = int(time.time()) + 102

        self.log.info("Test 1: Non-NULLDUMMY base multisig transaction is invalid")
        test1_tx = create_transaction(self.nodes[0], coinbase_txid[0], address, 46)
        test3_txs = [CTransaction(test1_tx)]
        add_dummy(test1_tx)
        assert_raises_rpc_error(-26, NULLDUMMY_ERROR, self.nodes[0].sendrawtransaction, bytes_to_hex_str(test1_tx.serialize_with_witness()), True)
        self.block_submit(self.nodes[0], [test1_tx])

        self.log.info("Test 2: Non-NULLDUMMY P2WSH multisig transaction invalid")
        test2_tx = create_transaction(self.nodes[0], coinbase_txid[1], wit_address, 48)
        test3_txs.append(CTransaction(test2_tx))
        test2_tx.wit.vtxinwit[0].scriptWitness.stack[0] = b'\x01'
        assert_raises_rpc_error(-26, NULLDUMMY_ERROR, self.nodes[0].sendrawtransaction, bytes_to_hex_str(test2_tx.serialize_with_witness()), True)
        self.block_submit(self.nodes[0], [test2_tx], True)

        self.log.info("Test 3: NULLDUMMY compliant base/witness transactions should be accepted to mempool and in block")
        for i in test3_txs:
            self.nodes[0].sendrawtransaction(bytes_to_hex_str(i.serialize_with_witness()), True)
        self.block_submit(self.nodes[0], test3_txs, True, True)

    def block_submit(self, node, txs, witness=False, accept=False):
        block = create_block(self.tip, create_coinbase(self.lastblockheight + 1), self.lastblocktime + 1)
        block.nVersion = 4
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        witness and add_witness_commitment(block)
        block.rehash()
        block.solve()
        node.submitblock(bytes_to_hex_str(block.serialize(True)))
        if (accept):
            assert_equal(node.getbestblockhash(), block.hash)
            self.tip = block.sha256
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert_equal(node.getbestblockhash(), self.lastblockhash)

if __name__ == '__main__':
    NULLDUMMYTest().main()
