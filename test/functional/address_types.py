#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the wallet can send and receive using all combinations of address types."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class AddressTypeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [["-addresstype=legacy"], ["-addresstype=p2sh"], ["-addresstype=p2sh", "-changetype=bech32"], ["-addresstype=bech32"]]

    def run_test(self):
        # Mine a recent block to bring nodes out of IBD
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        for c in range(4):
            multisig = c >= 2
            for n in range(4):
                old_balances = [self.nodes[i].getbalance() for i in range(4)]
                to_send = (old_balances[n] / 101).quantize(Decimal("0.00000001")) * 10
                sends = {}
                for k in range(4):
                    i = (n + k) % 4
                    if not multisig:
                        address = self.nodes[i].getnewaddress()
                    else:
                        addr1 = self.nodes[i].getnewaddress()
                        addr2 = self.nodes[i].getnewaddress()
                        address = self.nodes[i].addmultisigaddress(2, [addr1, addr2])
                    # Do some sanity checking on the created address
                    info = self.nodes[i].validateaddress(address)
                    assert(info['isvalid'])
                    assert(info['ismine'])
                    assert_equal(info['isscript'], multisig or i == 1 or i == 2)
                    assert_equal(info['iswitness'], i == 3)
                    if (info['isscript']):
                        assert_equal(info['script'], 'multisig' if multisig else 'witness_v0_keyhash')
                    else:
                        assert('script' not in info)
                    if (not multisig and (i == 1 or i == 2)):
                        assert('embedded' in info)
                        assert(not info['embedded']['isscript'])
                        assert(info['embedded']['iswitness'])
                        assert_equal(info['pubkey'], info['embedded']['pubkey'])
                    else:
                        assert('embedded' not in info)
                    # In each iteration, one node sends 10/101th of its balance to itself, 20/1011ths to the next peer,
                    # 30/101ths to the one after that, and 40/101ths to the remaining one.
                    sends[address] = to_send * (1 + k)
                self.nodes[n].sendmany("", sends)
                sync_mempools(self.nodes)
                unconf_balances = [self.nodes[i].getunconfirmedbalance() for i in range(4)]
                self.nodes[0].generate(1)
                sync_blocks(self.nodes)
                new_balances = [self.nodes[i].getbalance() for i in range(4)]
                for k in range(3):
                    i = (n + k + 1) % 4
                    assert_equal(unconf_balances[i], to_send * (2 + k))
                    assert_equal(new_balances[i], old_balances[i] + to_send * (2 + k) + (50 if i == 0 else 0))

if __name__ == '__main__':
    AddressTypeTest().main()
