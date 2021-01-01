// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_STATS_H
#define BITCOIN_NODE_STATS_H

#include <amount.h>
#include <protocol.h>
#include <net_permissions.h>
#include <net_types.h>

#include <vector>

/** Connection-level statistics for a peer, retrieved from CConnman. */
class CNodeStats
{
public:
    NodeId nodeid;
    ServiceFlags nServices;
    bool fRelayTxes;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nLastTXTime;
    int64_t nLastBlockTime;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    std::string addrName;
    int nVersion;
    std::string cleanSubVer;
    bool fInbound;
    bool m_manual_connection;
    bool m_bip152_highbandwidth_to;
    bool m_bip152_highbandwidth_from;
    int m_starting_height;
    uint64_t nSendBytes;
    mapMsgCmdSize mapSendBytesPerMsgCmd;
    uint64_t nRecvBytes;
    mapMsgCmdSize mapRecvBytesPerMsgCmd;
    NetPermissionFlags m_permissionFlags;
    bool m_legacyWhitelisted;
    int64_t m_ping_usec;
    int64_t m_ping_wait_usec;
    int64_t m_min_ping_usec;
    CAmount minFeeFilter;
    // Our address, as reported by the peer
    std::string addrLocal;
    // Address of this peer
    CAddress addr;
    // Bind address of our side of the connection
    CAddress addrBind;
    // Name of the network the peer connected through
    std::string m_network;
    uint32_t m_mapped_as;
    std::string m_conn_type_string;
};

/** Application-level statistics for a peer, retrieved from PeerMan. */
struct CNodeStateStats {
    int m_misbehavior_score = 0;
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::vector<int> vHeightInFlight;
};

#endif // BITCOIN_NODE_STATSH
