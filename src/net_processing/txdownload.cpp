// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <limitedmap.h>
#include <net_processing/txdownload.h>
#include <random.h>

/** Maximum number of transactions to keep track of globally*/
static constexpr unsigned int MAX_GLOBAL_TX_ANNOUNCED{50000};
/** How many microseconds to delay requesting transactions from inbound peers */
static constexpr std::chrono::microseconds INBOUND_PEER_TX_DELAY{std::chrono::seconds{2}};
/** Maximum delay (in microseconds) for transaction requests to avoid biasing some peers over others. */
static constexpr std::chrono::microseconds MAX_GETDATA_RANDOM_DELAY{std::chrono::seconds{2}};
static_assert(INBOUND_PEER_TX_DELAY >= MAX_GETDATA_RANDOM_DELAY,
"To preserve security, MAX_GETDATA_RANDOM_DELAY should not exceed INBOUND_PEER_DELAY");
/** Maximum number of announced transactions from a peer */
static constexpr int32_t MAX_PEER_TX_ANNOUNCEMENTS{10000};
/** How long to wait (in microseconds) before expiring an in-flight getdata request to a peer */
static constexpr std::chrono::microseconds TX_EXPIRY_INTERVAL{GETDATA_TX_INTERVAL * 10};

// Keeps track of the time (in microseconds) when transactions were requested last time
limitedmap<uint256, std::chrono::microseconds> g_already_asked_for GUARDED_BY(cs_main)(MAX_GLOBAL_TX_ANNOUNCED);

void TxDownloadState::AddAnnouncedTx(uint256 hash, std::chrono::microseconds request_time)
{
    // Check if we have too many queued announcements from this peer,
    // or if we already have this announcement.
    if (m_txs.size() >= MAX_PEER_TX_ANNOUNCEMENTS || m_txs.count(hash)) return;

    std::shared_ptr<AnnouncedTx> announced_tx = std::make_shared<AnnouncedTx>(hash, request_time);
    m_txs.emplace(hash, announced_tx);
    m_announced_txs.emplace(announced_tx);
};

void TxDownloadState::RequeueTx(uint256 hash, std::chrono::microseconds request_time)
{
    auto it = m_txs.find(hash);
    if (it == m_txs.end()) return;
    m_announced_txs.erase(it->second);
    it->second->m_timestamp = request_time;
    m_announced_txs.insert(it->second);
};

void TxDownloadState::RequestSent(uint256 hash, std::chrono::microseconds request_time)
{
    auto it = m_txs.find(hash);
    if (it == m_txs.end()) return;
    m_announced_txs.erase(it->second);
    it->second->m_timestamp = request_time;
    m_requested_txs.insert(it->second);
}

void TxDownloadState::RemoveTx(uint256 hash)
{
    auto it = m_txs.find(hash);
    if (it == m_txs.end()) return;
    m_announced_txs.erase(it->second);
    m_requested_txs.erase(it->second);
    m_txs.erase(hash);
}

void TxDownloadState::ExpireOldAnnouncedTxs(std::chrono::microseconds current_time, std::vector<uint256>& expired_requests)
{
    if (m_check_expiry_timer > current_time) return;
    // On average, we do this check every TX_EXPIRY_INTERVAL. Randomize
    // so that we're not doing this for all peers at the same time.
    m_check_expiry_timer = current_time + TX_EXPIRY_INTERVAL / 2 + GetRandMicros(TX_EXPIRY_INTERVAL);

    while (m_requested_txs.size() != 0) {
        auto it = m_requested_txs.begin();
        // m_requested_txs are ordered by time. If we encounter a
        // transaction after the expiry time, we're done.
        if ((*it)->m_timestamp > current_time - TX_EXPIRY_INTERVAL) return;
        expired_requests.push_back((*it)->m_hash);
        RemoveTx((*it)->m_hash);
    }
}

bool TxDownloadState::GetAnnouncedTxToRequest(std::chrono::microseconds current_time, uint256& txid)
{
    if (m_requested_txs.size() >= MAX_PEER_TX_IN_FLIGHT) return false;
    if (m_announced_txs.size() == 0) return false;
    auto it = m_announced_txs.begin();
    // m_tx_process_time are ordered by time. If the first m_announced_txs
    // is after current time, there are no transactions to request.
    if ((*it)->m_timestamp > current_time) return false;

    txid = (*it)->m_hash;
    m_announced_txs.erase(it);
    return true;
}

void EraseTxRequest(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    g_already_asked_for.erase(txid);
}

std::chrono::microseconds GetTxRequestTime(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto it = g_already_asked_for.find(txid);
    if (it != g_already_asked_for.end()) {
        return it->second;
    }
    return {};
}

void UpdateTxRequestTime(const uint256& txid, std::chrono::microseconds request_time) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    auto it = g_already_asked_for.find(txid);
    if (it == g_already_asked_for.end()) {
        g_already_asked_for.insert(std::make_pair(txid, request_time));
    } else {
        g_already_asked_for.update(it, request_time);
    }
}

std::chrono::microseconds CalculateTxGetDataTime(const uint256& txid, std::chrono::microseconds current_time, bool use_inbound_delay) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    std::chrono::microseconds process_time;
    const auto last_request_time = GetTxRequestTime(txid);
    // First time requesting this tx
    if (last_request_time.count() == 0) {
        process_time = current_time;
    } else {
        // Randomize the delay to avoid biasing some peers over others (such as due to
        // fixed ordering of peer processing in ThreadMessageHandler)
        process_time = last_request_time + GETDATA_TX_INTERVAL + GetRandMicros(MAX_GETDATA_RANDOM_DELAY);
    }

    // We delay processing announcements from inbound peers
    if (use_inbound_delay) process_time += INBOUND_PEER_TX_DELAY;

    return process_time;
}
