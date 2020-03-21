#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for test_framework.key."""

import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.key import generate_privkey, SECP256K1_ORDER, sign_schnorr, verify_schnorr, compute_xonly_pubkey

def test_schnorr():
    # Test the Python Schnorr implementation
    byte_arrays = [generate_privkey() for _ in range(8)] + [v.to_bytes(32, 'big') for v in [0, SECP256K1_ORDER - 1, SECP256K1_ORDER, 2**256 - 1]]
    keys = {}
    for privkey in byte_arrays:  # build array of key/pubkey pairs
        pubkey, _ = compute_xonly_pubkey(privkey)
        if pubkey is not None:
            keys[privkey] = pubkey
    for msg in byte_arrays:  # test every combination of message, signing key, verification key
        for sign_privkey, sign_pubkey in keys.items():
            sig = sign_schnorr(sign_privkey, msg)
            for verify_privkey, verify_pubkey in keys.items():
                if verify_privkey == sign_privkey:
                    assert(verify_schnorr(verify_pubkey, sig, msg))
                    sig = list(sig)
                    sig[random.randrange(64)] ^= (1 << (random.randrange(8)))  # damaging signature should break things
                    sig = bytes(sig)
                assert(not verify_schnorr(verify_pubkey, sig, msg))

class FrameworkTestKey(BitcoinTestFramework):
    def setup_network(self):
        pass

    def set_test_params(self):
        self.num_nodes = 0

    def run_test(self):
        test_schnorr()

if __name__ == '__main__':
    FrameworkTestKey().main()
