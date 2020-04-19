// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDOWNLOAD_H
#define BITCOIN_TXDOWNLOAD_H

#include <uint256.h>

#include <chrono>
#include <map>
#include <set>

/*
* State associated with transaction download.
 *
 * Tx download algorithm:
 *
 *   When inv comes in, queue up (process_time, txid) inside the peer's
 *   CNodeState (m_tx_process_time) as long as m_tx_announced for the peer
 *   isn't too big (MAX_PEER_TX_ANNOUNCEMENTS).
 *
 *   The process_time for a transaction is set to nNow for outbound peers,
 *   nNow + 2 seconds for inbound peers. This is the time at which we'll
 *   consider trying to request the transaction from the peer in
 *   SendMessages(). The delay for inbound peers is to allow outbound peers
 *   a chance to announce before we request from inbound peers, to prevent
 *   an adversary from using inbound connections to blind us to a
 *   transaction (InvBlock).
 *
 *   When we call SendMessages() for a given peer,
 *   we will loop over the transactions in m_tx_process_time, looking
 *   at the transactions whose process_time <= nNow. We'll request each
 *   such transaction that we don't have already and that hasn't been
 *   requested from another peer recently, up until we hit the
 *   MAX_PEER_TX_IN_FLIGHT limit for the peer. Then we'll update
 *   g_already_asked_for for each requested txid, storing the time of the
 *   GETDATA request. We use g_already_asked_for to coordinate transaction
 *   requests amongst our peers.
 *
 *   For transactions that we still need but we have already recently
 *   requested from some other peer, we'll reinsert (process_time, txid)
 *   back into the peer's m_tx_process_time at the point in the future at
 *   which the most recent GETDATA request would time out (ie
 *   GETDATA_TX_INTERVAL + the request time stored in g_already_asked_for).
 *   We add an additional delay for inbound peers, again to prefer
 *   attempting download from outbound peers first.
 *   We also add an extra small random delay up to 2 seconds
 *   to avoid biasing some peers over others. (e.g., due to fixed ordering
 *   of peer processing in ThreadMessageHandler).
 *
 *   When we receive a transaction from a peer, we remove the txid from the
 *   peer's m_tx_in_flight set and from their recently announced set
 *   (m_tx_announced).  We also clear g_already_asked_for for that entry, so
 *   that if somehow the transaction is not accepted but also not added to
 *   the reject filter, then we will eventually redownload from other
 *   peers.
 */
struct TxDownloadState {
    /* Track when to attempt download of announced transactions (process
     * time in micros -> txid)
     */
    std::multimap<std::chrono::microseconds, uint256> m_tx_process_time;

    //! Store all the transactions a peer has recently announced
    std::set<uint256> m_tx_announced;

    //! Store transactions which were requested by us, with timestamp
    std::map<uint256, std::chrono::microseconds> m_tx_in_flight;

    //! Periodically check for stuck getdata requests
    std::chrono::microseconds m_check_expiry_timer{0};
};

#endif // BITCOIN_TXDOWNLOAD_H
