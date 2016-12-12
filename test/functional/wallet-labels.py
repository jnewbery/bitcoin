#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet label API"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class Label:
    def __init__(self, name):
        self.name = name
        # Current default "label address" associated with this label.
        self.label_address = None
        # List of all addresses assigned with this label
        self.addresses = []

    def add_address(self, address, is_label_address):
        assert_equal(address not in self.addresses, True)
        if is_label_address:
            self.label_address = address
        self.addresses.append(address)

    def verify(self, node):
        if self.label_address is not None:
            assert self.label_address in self.addresses
            assert_equal(node.getlabeladdress(self.name), self.label_address)

        for address in self.addresses:
            assert_equal(
                node.getlabel(address),
                {"name": self.name,
                 "purpose": "receive",
                 "destdata": {}})

        assert_equal(
            node.getaddressesbylabel(self.name),
            {address: {
                "purpose": "receive"
            } for address in self.addresses})

def overwrite_label(node, old_label, address_idx, is_label_address, new_label):
    address = old_label.addresses[address_idx]
    assert_equal(is_label_address, address == old_label.label_address)

    node.setlabel(address, new_label.name)

    if old_label.name != new_label.name:
        del old_label.addresses[address_idx]
        new_label.add_address(address, False)

        # Calling setlabel on an address which was previously the default
        # "label address" of a different label should cause that label to no
        # longer have any default "label address" at all, and for
        # getlabeladdress to return a brand new address.
        if is_label_address:
            new_address = node.getlabeladdress(old_label.name)
            assert_equal(new_address not in new_label.addresses, True)
            old_label.add_address(new_address, True)

    old_label.verify(node)
    new_label.verify(node)

class WalletLabelsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        amount_to_send = 1.0
        labels = [Label(name) for name in ("a", "b", "c", "d", "e")]

        # Check that there's no UTXO on the node, and generate a spendable
        # balance.
        assert_equal(len(node.listunspent()), 0)
        node.generate(101)
        assert_equal(node.getbalance(), 50)

        # Create an address for each label and make sure subsequent label API
        # calls recognize the association.
        for label in labels:
            label.add_address(node.getlabeladdress(label.name), True)
            label.verify(node)

        # Check all labels are returned by listlabels.
        assert_equal(node.listlabels(),
                     [""] + [label.name for label in labels])

        # Send a transaction to each address, and make sure this forces
        # getlabeladdress to generate new unused addresses.
        for label in labels:
            node.sendtoaddress(label.label_address, amount_to_send)
            label.add_address(node.getlabeladdress(label.name), True)
            label.verify(node)

        # Mine block to confirm sends, then check the amounts received.
        node.generate(1)
        for label in labels:
            assert_equal(
                node.getreceivedbyaddress(label.addresses[0]), amount_to_send)
            # FIXME: Uncomment after API getreceivedbylabel is added
            # (see https://github.com/bitcoin/bitcoin/pull/7729#issuecomment-206927479)
            # assert_equal(node.getreceivedbylabel(label.name), amount_to_send)

        # Check that setlabel can add a label to a new unused address.
        for label in labels:
            address = node.getlabeladdress("")
            node.setlabel(address, label.name)
            label.add_address(address, False)
            label.verify(node)

        # Check that setlabel can safely overwrite the label of an address with
        # a different label.
        overwrite_label(node, labels[0], 0, False, labels[1])

        # Check that setlabel can safely overwrite the label of an address
        # which is the default "label address" of a different label.
        overwrite_label(node, labels[0], 0, True, labels[1])

        # Check that setlabel can safely overwrite the label of an address
        # which already has the same label, effectively performing a no-op.
        overwrite_label(node, labels[2], 0, False, labels[2])

        # Check that setlabel can safely overwrite the label of an address
        # which already has the same label, and which is the default "label
        # address" of that label, effectively performing a no-op.
        overwrite_label(node, labels[2], 1, True, labels[2])

if __name__ == '__main__':
    WalletLabelsTest().main()
