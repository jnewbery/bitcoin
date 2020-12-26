// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include <consensus/params.h>
#include <net.h>
#include <sync.h>
#include <txrequest.h>
#include <validationinterface.h>

class CChainParams;
class CTxMemPool;
class ChainstateManager;

extern RecursiveMutex cs_main;
extern RecursiveMutex g_cs_orphans;

/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
/** Default number of orphan+recently-replaced txn to keep around for block reconstruction */
static const unsigned int DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100;
static const bool DEFAULT_PEERBLOOMFILTERS = false;
static const bool DEFAULT_PEERBLOCKFILTERS = false;
/** Threshold for marking a node to be discouraged, e.g. disconnected and added to the discouragement filter. */
static const int DISCOURAGEMENT_THRESHOLD{100};

struct CNodeStateStats {
    int m_misbehavior_score = 0;
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::vector<int> vHeightInFlight;
};

class PeerManager : public CValidationInterface, public NetEventsInterface {
public:
    /** Evict extra outbound peers. If we think our tip may be stale, connect to an extra outbound */
    virtual void CheckForStaleTipAndEvictPeers() = 0;

    /** Relay transaction to every node */
    virtual void RelayTransaction(const uint256& txid, const uint256& wtxid) EXCLUSIVE_LOCKS_REQUIRED(cs_main) = 0;

public: // exposed as debugging info for RPC
    /** Get statistics from node state */
    virtual bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) = 0;

    /** Whether this node ignores txs received over p2p. */
    virtual bool IgnoresIncomingTxs() = 0;

public: // exposed for tests
    /**
     * Increment peer's misbehavior score. If the new value >= DISCOURAGEMENT_THRESHOLD, mark the node
     * to be discouraged, meaning the peer might be disconnected and added to the discouragement filter.
     * Public for unit testing.
     */
    virtual void Misbehaving(const NodeId pnode, const int howmuch, const std::string& message) = 0;

    /** Process a single message from a peer. Public for fuzz testing */
    virtual void ProcessMessage(CNode& pfrom, const std::string& msg_type, CDataStream& vRecv,
                        const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) = 0;

    struct COrphanTx {
        CTransactionRef tx;
        NodeId fromPeer;
        int64_t nTimeExpire;
        size_t list_pos;
    };

    virtual bool AddOrphanTx(const CTransactionRef& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(g_cs_orphans) = 0;
    virtual void EraseOrphansFor(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(g_cs_orphans) = 0;
    virtual unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans) = 0;
    virtual void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) = 0;

    /** Map from txid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    std::map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(g_cs_orphans);

    virtual ~PeerManager() { }
};

std::unique_ptr<PeerManager> make_PeerManager(const CChainParams& chainparams, CConnman& connman, BanMan* banman,
                CScheduler& scheduler, ChainstateManager& chainman, CTxMemPool& pool,
                bool ignore_incoming_txs);


#endif // BITCOIN_NET_PROCESSING_H
