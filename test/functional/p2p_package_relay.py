#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Package Relay"""

from decimal import Decimal

from test_framework.messages import (
    CInv,
    CTransaction,
    FromHex,
    msg_inv,
    MSG_WTX,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class P2PPackageRelayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        self.setup_clean_chain = True

    def create_raw_cpfp(self):
        """Build a parent, child transaction pair: parent has 0 fee, child has 0.001BTC fee.
        Return (tx_parent, tx_child, hex_parent, hex_child)
        """
        node = self.nodes[0]
        first_coin = self.coins.pop()
        inputs = [{"txid": first_coin["txid"], "vout": 0}]
        outputs = {self.address : first_coin["amount"]}
        raw_parent = node.createrawtransaction(inputs, outputs)
        signed_parent = node.signrawtransactionwithkey(raw_parent, self.privkeys)
        assert signed_parent["complete"]
        hex_parent = signed_parent["hex"]
        tx_parent = FromHex(CTransaction(), hex_parent)

        prevtxs = [{
            "txid": tx_parent.rehash(),
            "vout": 0,
            "scriptPubKey": tx_parent.vout[0].scriptPubKey.hex(),
            "amount": first_coin["amount"],
        }]
        inputs = [{"txid": tx_parent.rehash(), "vout": 0}]
        outputs = {self.address: first_coin["amount"] - Decimal("0.001")}
        raw_child = node.createrawtransaction(inputs, outputs)
        signed_child = node.signrawtransactionwithkey(raw_child, self.privkeys, prevtxs)
        assert signed_child["complete"]
        hex_child = signed_child["hex"]
        tx_child = FromHex(CTransaction(), hex_child)

        testres_parent = node.testmempoolaccept([hex_parent])
        assert not testres_parent[0]["allowed"]
        assert_equal(testres_parent[0]["reject-reason"], "min relay fee not met")
        testres_package = node.testmempoolaccept([hex_parent, hex_child])
        assert all(res["allowed"] for res in testres_package)
        return (tx_parent, tx_child, hex_parent, hex_child)

    def run_test(self):
        self.log.info("Generate blocks to create UTXOs")
        node = self.nodes[0]
        self.privkeys = [node.get_deterministic_priv_key().key]
        self.address = node.get_deterministic_priv_key().address
        self.coins = []
        # The last 100 coinbase transactions are premature
        for b in node.generatetoaddress(200, self.address)[:100]:
            coinbase = node.getblock(blockhash=b, verbosity=2)["tx"][0]
            self.coins.append({
                "txid": coinbase["txid"],
                "amount": coinbase["vout"][0]["value"],
                "scriptPubKey": coinbase["vout"][0]["scriptPubKey"],
            })

        self.sync_all()

        self.log.info("Create a package (parent A, child B) where A has fee 0 and B has fee 0.001")
        (tx_parent, tx_child, hex_parent, hex_child) = self.create_raw_cpfp()

        self.log.info("Send child B to node3 and node4")
        peer3 = self.nodes[3].add_p2p_connection(P2PDataStore())
        peer3.send_txs_and_test([tx_child], self.nodes[3], success=False, expect_disconnect=False,
                reject_reason="bad-txns-inputs-missingorspent")
        peer3.peer_disconnect()
        peer4 = self.nodes[4].add_p2p_connection(P2PDataStore())
        peer4.send_txs_and_test([tx_child], self.nodes[4], success=False, expect_disconnect=False,
                reject_reason="bad-txns-inputs-missingorspent")
        # node4 will not ask for tx_child from node3 if it has an outstanding request to peer4
        peer4.peer_disconnect()

        self.log.info("Submit package to node0 and wait for it to propagate")
        self.nodes[0].submitrawpackage(package=[hex_parent, hex_child])
        self.wait_until(lambda: len(self.nodes[5].getrawmempool()) == 2)

if __name__ == "__main__":
    P2PPackageRelayTest().main()
