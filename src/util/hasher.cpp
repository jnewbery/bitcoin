// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/hasher.h>

// Specialization for txid
size_t InnerHashFunction(uint64_t k0, uint64_t k1, const uint256& txid)
{
    return SipHashUint256(k0, k1, txid);
}

// Specialization for outpoint
//
// Having the hash noexcept allows libstdc++'s unordered_map to recalculate the
// hash during rehash, so it does not have to cache the value. This reduces
// node's memory by sizeof(size_t). The required recalculation has a slight
// performance penalty (around 1.6%), but this is compensated by memory savings
// of about 9% which allow for a larger dbcache setting.
//
// @see https://gcc.gnu.org/onlinedocs/gcc-9.2.0/libstdc++/manual/manual/unordered_associative.html

size_t InnerHashFunction(uint64_t k0, uint64_t k1, const COutPoint& out) noexcept
{
    return SipHashUint256Extra(k0, k1, out.hash, out.n);
}

// Specialization for span
size_t InnerHashFunction(uint64_t k0, uint64_t k1, const Span<const unsigned char>& span)
{
    return CSipHasher(k0, k1).Write(span.data(), span.size()).Finalize();
}
