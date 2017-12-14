#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the wallet can send and receive using all combinations of address types.

There are 4 nodes-under-test:
    - node0 uses legacy addresses
    - node1 uses p2sh addresses
    - node2 uses p2sh addresses and bech32 addresses for change
    - node3 uses bech32 addresses

node4 exists to generate new blocks.

The script is a series of tests, iterating over the 4 nodes. In each iteration
of the test, one node sends:
    - 10/101th of its balance to itself
    - 20/101th to the next node
    - 30/101th to the node after that
    - 40/101th to the remaining node
    - 1/101th remains as fee+change

Iterate over each node for single key addresses, and then over each node for
multisig addresses. Repeat twice for good measure."""

from decimal import Decimal
import itertools

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, connect_nodes_bi, sync_blocks, sync_mempools

class AddressTypeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 5
        self.extra_args = [["-addresstype=legacy"], ["-addresstype=p2sh"], ["-addresstype=p2sh", "-changetype=bech32"], ["-addresstype=bech32"], []]

    def setup_network(self):
        self.setup_nodes()

        # Fully mesh-connect nodes for faster mempool sync
        for i, j in itertools.product(range(self.num_nodes), repeat=2):
            if i > j:
                connect_nodes_bi(self.nodes, i, j)
        self.sync_all()

    def get_balances(self, confirmed=True):
        """Return a list of confirmed or unconfirmed balances."""
        if confirmed:
            return [self.nodes[i].getbalance() for i in range(4)]
        else:
            return [self.nodes[i].getunconfirmedbalance() for i in range(4)]

    def run_test(self):
        # Mine 101 blocks on node4 to bring nodes out of IBD and make sure that
        # no coinbases are maturing for the nodes-under-test during the test
        self.nodes[4].generate(101)
        sync_blocks(self.nodes)

        for _, multisig, from_node in itertools.product(range(2), [False, True], range(4)):
            self.log.info("Sending from node {} ({}) with{} multisig".format(from_node, self.extra_args[from_node], "" if multisig else "out"))
            old_balances = self.get_balances()
            self.log.debug("Old balances are {}".format(old_balances))
            to_send = (old_balances[from_node] / 101).quantize(Decimal("0.00000001"))
            sends = {}

            self.log.debug("Prepare sends")
            for n, to_node in enumerate(range(from_node, from_node + 4)):
                to_node %= 4
                if not multisig:
                    address = self.nodes[to_node].getnewaddress()
                else:
                    addr1 = self.nodes[to_node].getnewaddress()
                    addr2 = self.nodes[to_node].getnewaddress()
                    address = self.nodes[to_node].addmultisigaddress(2, [addr1, addr2])

                # Do some sanity checking on the created address
                info = self.nodes[to_node].validateaddress(address)
                assert(info['isvalid'])
                assert(info['ismine'])
                assert_equal(info['isscript'], multisig or to_node == 1 or to_node == 2)
                assert_equal(info['iswitness'], to_node == 3)
                if (info['isscript']):
                    assert_equal(info['script'], 'multisig' if multisig else 'witness_v0_keyhash')
                else:
                    assert('script' not in info)
                if (not multisig and (to_node == 1 or to_node == 2)):
                    assert('embedded' in info)
                    assert(not info['embedded']['isscript'])
                    assert(info['embedded']['iswitness'])
                    assert_equal(info['pubkey'], info['embedded']['pubkey'])
                else:
                    assert('embedded' not in info)

                sends[address] = to_send * 10 * (1 + n)

            self.log.debug("Sending: {}".format(sends))
            self.nodes[from_node].sendmany("", sends)
            sync_mempools(self.nodes)

            unconf_balances = self.get_balances(False)
            self.log.debug("Check unconfirmed balances: {}".format(unconf_balances))
            assert_equal(unconf_balances[from_node], 0)
            for n, to_node in enumerate(range(from_node + 1, from_node + 4)):
                to_node %= 4
                assert_equal(unconf_balances[to_node], to_send * 10 * (2 + n))

            # node4 collects fee and block subsidy to keep accounting simple
            self.nodes[4].generate(1)
            sync_blocks(self.nodes)

            new_balances = self.get_balances()
            self.log.debug("Check new balances: {}".format(new_balances))
            # We don't know what fee was set, so we can only check bounds on the balance of the sending node
            assert_greater_than(new_balances[from_node], to_send * 10)
            assert_greater_than(to_send * 11, new_balances[from_node])
            for n, to_node in enumerate(range(from_node + 1, from_node + 4)):
                to_node %= 4
                assert_equal(new_balances[to_node], old_balances[to_node] + to_send * 10 * (2 + n))

if __name__ == '__main__':
    AddressTypeTest().main()
