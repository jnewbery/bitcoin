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

// Keeps track of the time (in microseconds) when transactions were requested last time
limitedmap<uint256, std::chrono::microseconds> g_already_asked_for GUARDED_BY(cs_main)(MAX_GLOBAL_TX_ANNOUNCED);

void TxDownloadState::AddAnnouncedTx(uint256 hash, std::chrono::microseconds request_time)
{
    if (m_tx_announced.size() >= MAX_PEER_TX_ANNOUNCEMENTS ||
            m_tx_process_time.size() >= MAX_PEER_TX_ANNOUNCEMENTS ||
            m_tx_announced.count(hash)) {
        // Too many queued announcements from this peer, or we already have
        // this announcement
        return;
    }
    m_tx_announced.insert(hash);
    m_tx_process_time.emplace(request_time, hash);
};

void TxDownloadState::RequeueTx(uint256 hash, std::chrono::microseconds request_time)
{
    m_tx_process_time.emplace(request_time, hash);
};

void TxDownloadState::RequestSent(uint256 hash, std::chrono::microseconds request_time)
{
    m_tx_in_flight.emplace(hash, request_time);
}

void TxDownloadState::RemoveTx(uint256 hash)
{
    m_tx_announced.erase(hash);
    m_tx_in_flight.erase(hash);
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
