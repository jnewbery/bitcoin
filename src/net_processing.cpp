// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing.h>
#include <net_processing_impl.h>

std::unique_ptr<PeerManager> make_PeerManager(const CChainParams& chainparams, CConnman& connman, BanMan* banman,
                         CScheduler& scheduler, ChainstateManager& chainman, CTxMemPool& pool,
                         bool ignore_incoming_txs)
{
    return std::make_unique<PeerManagerImpl>(chainparams, connman, banman, scheduler, chainman, pool, ignore_incoming_txs);
}
