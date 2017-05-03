#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test HD Wallet keypool restore function.

Two nodes. Node1 is under test. Node0 is providing transactions and generating blocks.

- Start node1, shutdown and backup unencrypted wallet. Generate 110 keys (enough to drain the keypool). Store key
  90 (in the initial keypool) and key 110 (beyond the initial keypool). Send funds to key 90 and key 110.
- Restart node, encrypt wallet and backup encrypted wallet. Generate 110 keys (enough to drain the keypool). Store key
  90 (in the initial keypool) and key 110 (beyond the initial keypool). Send funds to key 90 and key 110.
- Stop node1, clear the datadir, move unencrypted wallet back into the datadir and restart node1.
- connect node1 to node0. Verify that they sync and node1 receives its funds.
- Stop node1, move encrypted wallet back into the datadir and restart node1.
- Verify that node1 fails to start up because it can't topup its keypool.
"""
import shutil

from test_framework.test_framework import BitcoinTestFramework, BITCOIND_PROC_WAIT_TIMEOUT
from test_framework.util import (
    assert_equal,
    assert_raises_jsonrpc,
    connect_nodes,
    connect_nodes_bi
)

class KeypoolRestoreTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-usehd=0'], ['-usehd=1', '-keypool=100', '-keypoolmin=20']]

    def run_test(self):
        tmpdir = self.options.tmpdir
        self.nodes[0].generate(101)

        self.log.info("Make backup of unencrypted wallet")

        self.stop_node(1)
        shutil.copyfile(tmpdir + "/node1/regtest/wallet.dat", tmpdir + "/hd.bak")
        self.nodes[1] = self.start_node(1, self.options.tmpdir, self.extra_args[1])

        self.log.info("Generate keys for unencrypted wallet")

        for _ in range(90):
            addr_unenc_oldpool = self.nodes[1].getnewaddress()
        for _ in range(20):
            addr_unenc_extpool = self.nodes[1].getnewaddress()

        self.stop_node(1)

        self.log.info("Make backup of encrypted wallet")

        shutil.copyfile(tmpdir + "/hd.bak", tmpdir + "/node1/regtest/wallet.dat")
        self.nodes[1] = self.start_node(1, self.options.tmpdir, self.extra_args[1])
        self.nodes[1].encryptwallet('test')
        self.bitcoind_processes[1].wait(timeout=BITCOIND_PROC_WAIT_TIMEOUT)
        # node will be stopped during encryption, now do a backup
        shutil.copyfile(tmpdir + "/node1/regtest/wallet.dat", tmpdir + "/hd.enc.bak")

        self.log.info("Generate keys for encrypted wallet")

        self.nodes[1] = self.start_node(1, self.options.tmpdir, self.extra_args[1])
        for _ in range(90):
            addr_enc_oldpool = self.nodes[1].getnewaddress()
        for _ in range(10):
            addr_enc_extpool = self.nodes[1].getnewaddress()
        # Keypool can't top up because the wallet is encrypted
        assert_raises_jsonrpc(-12, "Keypool ran out", self.nodes[1].getnewaddress)
        self.nodes[1].walletpassphrase("test", 10)
        for _ in range(10):
            addr_enc_extpool = self.nodes[1].getnewaddress()

        self.log.info("Send funds to encrypted and unencrypted wallets")

        self.nodes[0].sendtoaddress(addr_unenc_oldpool, 10)
        self.nodes[0].sendtoaddress(addr_enc_oldpool, 10)
        self.nodes[0].sendtoaddress(addr_unenc_extpool, 5)
        self.nodes[0].sendtoaddress(addr_enc_extpool, 5)
        self.nodes[0].generate(1)

        self.log.info("Restart with encrypted wallet - node should shut down")

        self.stop_node(1)
        shutil.rmtree(tmpdir + "/node1/regtest/chainstate")
        shutil.rmtree(tmpdir + "/node1/regtest/blocks")
        shutil.copyfile(tmpdir + "/hd.enc.bak", tmpdir + "/node1/regtest/wallet.dat")
        self.nodes[1] = self.start_node(1, self.options.tmpdir, self.extra_args[1])
        connect_nodes(self.nodes[0], 1)

        # node1 should shutdown because it can't topup its keypool
        self.bitcoind_processes[1].wait(2)

        self.log.info("Restart with unencrypted wallet")

        shutil.rmtree(tmpdir + "/node1/regtest/chainstate")
        shutil.rmtree(tmpdir + "/node1/regtest/blocks")
        shutil.copyfile(tmpdir + "/hd.bak", tmpdir + "/node1/regtest/wallet.dat")
        self.nodes[1] = self.start_node(1, self.options.tmpdir, self.extra_args[1])
        connect_nodes_bi(self.nodes, 0, 1)

        self.sync_all()

        assert_equal(self.nodes[1].getbalance(), 15)
        assert_equal(self.nodes[1].listtransactions()[0]['category'], "receive")

        # now check if we have marked all keys up to the used keypool key as used
        assert_equal(self.nodes[1].validateaddress(self.nodes[1].getnewaddress())['hdkeypath'], "m/0'/0'/111'")

if __name__ == '__main__':
    KeypoolRestoreTest().main()
