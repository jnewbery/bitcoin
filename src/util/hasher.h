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

template<typename T>
class GenericSaltedSipHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    GenericSaltedSipHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())),
                               k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

    // Specialization for txid
    size_t InnerHashFunction(const uint256& txid) const
    {
        return SipHashUint256(k0, k1, txid);
    }

    // Specialization for outpoint
    //
    //  Having the hash noexcept allows libstdc++'s unordered_map to recalculate
    // the hash during rehash, so it does not have to cache the value. This
    // reduces node's memory by sizeof(size_t). The required recalculation has
    // a slight performance penalty (around 1.6%), but this is compensated by
    // memory savings of about 9% which allow for a larger dbcache setting.
    //
    // @see https://gcc.gnu.org/onlinedocs/gcc-9.2.0/libstdc++/manual/manual/unordered_associative.html
    size_t InnerHashFunction(const COutPoint& out) const noexcept
    {
        return SipHashUint256Extra(k0, k1, out.hash, out.n);
    }

    // Specialization for span
    size_t InnerHashFunction(const Span<const unsigned char>& span) const
    {
        return CSipHasher(k0, k1).Write(span.data(), span.size()).Finalize();
    }

    size_t operator()(const T t) const { return InnerHashFunction(t); }
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
