// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_SETTINGS_H
#define BITCOIN_POLICY_SETTINGS_H

#include <policy/policy.h>

/** Default for -limitancestorcount, max number of in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_LIMIT = 25;
/** Default for -limitancestorsize, maximum kilobytes of tx + all in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_SIZE_LIMIT = 101;
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_LIMIT = 25;
/** Default for -limitdescendantsize, maximum kilobytes of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_SIZE_LIMIT = 101;

class CFeeRate;
class CTransaction;

// Policy settings which are configurable at runtime.
extern CFeeRate incrementalRelayFee;
extern CFeeRate dustRelayFee;
extern unsigned int nBytesPerSigOp;
extern bool fIsBareMultisigStd;

struct PackageLimits {
    unsigned int m_ancestor_limit;
    unsigned int m_ancestor_size_limit;
    unsigned int m_descendant_limit;
    unsigned int m_descendant_size_limit;
};

extern PackageLimits g_package_limits;

static inline bool IsStandardTx(const CTransaction& tx, std::string& reason)
{
    return IsStandardTx(tx, ::fIsBareMultisigStd, ::dustRelayFee, reason);
}

static inline int64_t GetVirtualTransactionSize(int64_t weight, int64_t sigop_cost)
{
    return GetVirtualTransactionSize(weight, sigop_cost, ::nBytesPerSigOp);
}

static inline int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t sigop_cost)
{
    return GetVirtualTransactionSize(tx, sigop_cost, ::nBytesPerSigOp);
}

#endif // BITCOIN_POLICY_SETTINGS_H
