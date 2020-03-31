// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TRANSACTION_H
#define BITCOIN_UTIL_TRANSACTION_H

#include <crypto/siphash.h>
#include <random.h>

class SaltedTxidHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;
public:
    SaltedTxidHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

    size_t operator()(const uint256& txid) const {
        return SipHashUint256(k0, k1, txid);
    }
};

#endif // BITCOIN_UTIL_TRANSACTION_H
