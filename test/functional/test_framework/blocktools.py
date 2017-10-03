#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for manipulating blocks and transactions."""

from .mininode import (
    CBlock,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    hash256,
    ser_string,
    ser_uint256,
    uint256_from_str,
)
from .script import CScript, OP_TRUE, OP_CHECKSIG, OP_RETURN

# The commitment header to place in the coinbase transaction output. See BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"

def create_block(hashprev, coinbase, nTime=None):
    """Create a block with regtest difficulty."""

    block = CBlock()
    if nTime is None:
        import time
        block.nTime = int(time.time() + 600)
    else:
        block.nTime = nTime
    block.hashPrevBlock = hashprev
    block.nBits = 0x207fffff  # Will break after a difficulty adjustment...
    block.vtx.append(coinbase)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

def get_witness_script(witness_root, witness_nonce):
    """Return the script to place in the coinbase transaction for the witness commitment."""

    witness_commitment = uint256_from_str(hash256(ser_uint256(witness_root) + ser_uint256(witness_nonce)))
    output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(witness_commitment)
    return CScript([OP_RETURN, output_data])

def add_witness_commitment(block, nonce=0):
    """Add a witness commitment to the block coinbase transaction output.

    See BIP 141 for block witness commitment rules."""

    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    block.vtx[0].vout.append(CTxOut(0, get_witness_script(witness_root, witness_nonce)))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()

def serialize_script_num(value):
    """Serialize a number into a script.

    This is used to put the block height into the coinbase transaction (see BIP 34)."""

    r = bytearray(0)
    if value == 0:
        return r
    neg = value < 0
    absvalue = -value if neg else value
    while (absvalue):
        r.append(int(absvalue & 0xff))
        absvalue >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return r

def create_coinbase(height, pubkey=None):
    """Create a coinbase transaction, assuming no miner fees.

    If pubkey is passed in, the coinbase output will be a P2PK output;
    otherwise an anyone-can-spend output."""

    coinbase = CTransaction()
    coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff),
                        ser_string(serialize_script_num(height)), 0xffffffff))
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = 50 * COIN
    halvings = int(height / 150)  # regtest
    coinbaseoutput.nValue >>= halvings
    if pubkey is not None:
        coinbaseoutput.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    else:
        coinbaseoutput.scriptPubKey = CScript([OP_TRUE])
    coinbase.vout = [coinbaseoutput]
    coinbase.calc_sha256()
    return coinbase

def create_transaction(prevtx, n, sig, value, scriptPubKey=CScript()):
    """Create a transaction.

    If the scriptPubKey is not specified, make it anyone-can-spend."""

    tx = CTransaction()
    assert(n < len(prevtx.vout))
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    tx.vout.append(CTxOut(value, scriptPubKey))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, fAccurate=True):
    """Return the legacy sigops count for the block."""
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, fAccurate)
    return count

def get_legacy_sigopcount_tx(tx, fAccurate=True):
    """Return the legacy sigops count for the transaction."""
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(fAccurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(fAccurate)
    return count
