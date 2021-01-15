// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_HASHER_H
#define BITCOIN_UTIL_HASHER_H

#include <crypto/siphash.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>

#include <limits>

// Specialization hash functions
size_t InnerHashFunction(uint64_t k0, uint64_t k1, const uint256& txid);
size_t InnerHashFunction(uint64_t k0, uint64_t k1, const COutPoint& out) noexcept;
size_t InnerHashFunction(uint64_t k0, uint64_t k1, const Span<const unsigned char>& span);

template<typename T>
class GenericSaltedSipHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    GenericSaltedSipHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())),
                               k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

    size_t operator()(const T t) const { return InnerHashFunction(k0, k1, t); }
};

using SaltedTxidHasher = GenericSaltedSipHasher<const uint256&>;
using SaltedOutpointHasher = GenericSaltedSipHasher<const COutPoint&>;
using SaltedSipHasher = GenericSaltedSipHasher<const Span<const unsigned char>&>;

struct FilterHeaderHasher
{
    size_t operator()(const uint256& hash) const { return ReadLE64(hash.begin()); }
};

/**
 * We're hashing a nonce into the entries themselves, so we don't need extra
 * blinding in the set hash computation.
 *
 * This may exhibit platform endian dependent behavior but because these are
 * nonced hashes (random) and this state is only ever used locally it is safe.
 * All that matters is local consistency.
 */
class SignatureCacheHasher
{
public:
    template <uint8_t hash_select>
    uint32_t operator()(const uint256& key) const
    {
        static_assert(hash_select <8, "SignatureCacheHasher only has 8 hashes available.");
        uint32_t u;
        std::memcpy(&u, key.begin()+4*hash_select, 4);
        return u;
    }
};

struct BlockHasher
{
    // this used to call `GetCheapHash()` in uint256, which was later moved; the
    // cheap hash function simply calls ReadLE64() however, so the end result is
    // identical
    size_t operator()(const uint256& hash) const { return ReadLE64(hash.begin()); }
};

#endif // BITCOIN_UTIL_HASHER_H
