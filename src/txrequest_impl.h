// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXREQUEST_IMPL_H
#define BITCOIN_TXREQUEST_IMPL_H

#include <txrequest.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

#include <chrono>
#include <unordered_map>

//! Type alias for sequence numbers.
using SequenceNumber = uint64_t;
//! Type alias for priorities.
using Priority = uint64_t;

/** The various states a (txhash,peer) pair can be in.
 *
 * Note that CANDIDATE is split up into 3 substates (DELAYED, BEST, READY), allowing more efficient implementation.
 * Also note that the sorting order of ByTxHashView relies on the specific order of values in this enum.
 *
 * Expected behaviour is:
 *   - When first announced by a peer, the state is CANDIDATE_DELAYED until reqtime is reached.
 *   - Announcements that have reached their reqtime but not been requested will be either CANDIDATE_READY or
 *     CANDIDATE_BEST. Neither of those has an expiration time; they remain in that state until they're requested or
 *     no longer needed. CANDIDATE_READY announcements are promoted to CANDIDATE_BEST when they're the best one left.
 *   - When requested, an announcement will be in state REQUESTED until expiry is reached.
 *   - If expiry is reached, or the peer replies to the request (either with NOTFOUND or the tx), the state becomes
 *     COMPLETED.
 */
enum class State : uint8_t {
    /** A CANDIDATE announcement whose reqtime is in the future. */
    CANDIDATE_DELAYED,
    /** A CANDIDATE announcement that's not CANDIDATE_DELAYED or CANDIDATE_BEST. */
    CANDIDATE_READY,
    /** The best CANDIDATE for a given txhash; only if there is no REQUESTED announcement already for that txhash.
     *  The CANDIDATE_BEST is the highest-priority announcement among all CANDIDATE_READY (and _BEST) ones for that
     *  txhash. */
    CANDIDATE_BEST,
    /** A REQUESTED announcement. */
    REQUESTED,
    /** A COMPLETED announcement. */
    COMPLETED,
};

enum class WaitState {
    //! Used for announcements that need efficient testing of "is their timestamp in the future?".
    FUTURE_EVENT,
    //! Used for announcements whose timestamp is not relevant.
    NO_EVENT,
    //! Used for announcements that need efficient testing of "is their timestamp in the past?".
    PAST_EVENT,
};

/** An announcement. This is the data we track for each txid or wtxid that is announced to us by each peer. */
struct Announcement {
    /** Txid or wtxid that was announced. */
    const uint256 m_txhash;
    /** For CANDIDATE_{DELAYED,BEST,READY} the reqtime; for REQUESTED the expiry. */
    std::chrono::microseconds m_time;
    /** What peer the request was from. */
    const NodeId m_peer;
    /** What sequence number this announcement has. */
    const SequenceNumber m_sequence : 59;
    /** Whether the request is preferred. */
    const bool m_preferred : 1;
    /** Whether this is a wtxid request. */
    const bool m_is_wtxid : 1;

    /** What state this announcement is in. */
    State m_state : 3;

    /** Whether this announcement is selected. There can be at most 1 selected peer per txhash. */
    bool IsSelected() const
    {
        return m_state == State::CANDIDATE_BEST || m_state == State::REQUESTED;
    }

    /** Whether this announcement is waiting for a certain time to pass. */
    bool IsWaiting() const
    {
        return m_state == State::REQUESTED || m_state == State::CANDIDATE_DELAYED;
    }

    /** Whether this announcement can feasibly be selected if the current IsSelected() one disappears. */
    bool IsSelectable() const
    {
        return m_state == State::CANDIDATE_READY || m_state == State::CANDIDATE_BEST;
    }

    WaitState GetWaitState() const
    {
        if (IsWaiting()) return WaitState::FUTURE_EVENT;
        if (IsSelectable()) return WaitState::PAST_EVENT;
        return WaitState::NO_EVENT;
    }

    /** Construct a new announcement from scratch, initially in CANDIDATE_DELAYED state. */
    Announcement(const GenTxid& gtxid, NodeId peer, bool preferred, std::chrono::microseconds reqtime,
        SequenceNumber sequence) :
        m_txhash(gtxid.GetHash()), m_time(reqtime), m_peer(peer), m_sequence(sequence), m_preferred(preferred),
        m_is_wtxid(gtxid.IsWtxid()), m_state(State::CANDIDATE_DELAYED) {}
};

/** A functor with embedded salt that computes priority of an announcement.
 *
 * Higher priorities are selected first.
 */
class PriorityComputer {
    const uint64_t m_k0, m_k1;
public:
    explicit PriorityComputer(bool deterministic) :
        m_k0{deterministic ? 0 : GetRand(0xFFFFFFFFFFFFFFFF)},
        m_k1{deterministic ? 0 : GetRand(0xFFFFFFFFFFFFFFFF)} {}

    Priority operator()(const uint256& txhash, NodeId peer, bool preferred) const
    {
        uint64_t low_bits = CSipHasher(m_k0, m_k1).Write(txhash.begin(), txhash.size()).Write(peer).Finalize() >> 1;
        return low_bits | uint64_t{preferred} << 63;
    }

    Priority operator()(const Announcement& ann) const
    {
        return operator()(ann.m_txhash, ann.m_peer, ann.m_preferred);
    }
};

// Definitions for the 3 indexes used in the main data structure.
//
// Each index has a By* type to identify it, a By*View data type to represent the view of announcement it is sorted
// by, and an By*ViewExtractor type to convert an announcement into the By*View type.
// See https://www.boost.org/doc/libs/1_58_0/libs/multi_index/doc/reference/key_extraction.html#key_extractors
// for more information about the key extraction concept.

// The ByPeer index is sorted by (peer, state == CANDIDATE_BEST, txhash)
//
// Uses:
// * Looking up existing announcements by peer/txhash, by checking both (peer, false, txhash) and
//   (peer, true, txhash).
// * Finding all CANDIDATE_BEST announcements for a given peer in GetRequestable.
struct ByPeer {};
using ByPeerView = std::tuple<NodeId, bool, const uint256&>;
struct ByPeerViewExtractor
{
    using result_type = ByPeerView;
    result_type operator()(const Announcement& ann) const
    {
        return ByPeerView{ann.m_peer, ann.m_state == State::CANDIDATE_BEST, ann.m_txhash};
    }
};

// The ByTxHash index is sorted by (txhash, state, priority).
//
// Note: priority == 0 whenever state != CANDIDATE_READY.
//
// Uses:
// * Deleting all announcements with a given txhash in ForgetTxHash.
// * Finding the best CANDIDATE_READY to convert to CANDIDATE_BEST, when no other CANDIDATE_READY or REQUESTED
//   announcement exists for that txhash.
// * Determining when no more non-COMPLETED announcements for a given txhash exist, so the COMPLETED ones can be
//   deleted.
struct ByTxHash {};
using ByTxHashView = std::tuple<const uint256&, State, Priority>;
class ByTxHashViewExtractor {
    const PriorityComputer& m_computer;
public:
    ByTxHashViewExtractor(const PriorityComputer& computer) : m_computer(computer) {}
    using result_type = ByTxHashView;
    result_type operator()(const Announcement& ann) const
    {
        const Priority prio = (ann.m_state == State::CANDIDATE_READY) ? m_computer(ann) : 0;
        return ByTxHashView{ann.m_txhash, ann.m_state, prio};
    }
};

// The ByTime index is sorted by (wait_state, time).
//
// All announcements with a timestamp in the future can be found by iterating the index forward from the beginning.
// All announcements with a timestamp in the past can be found by iterating the index backwards from the end.
//
// Uses:
// * Finding CANDIDATE_DELAYED announcements whose reqtime has passed, and REQUESTED announcements whose expiry has
//   passed.
// * Finding CANDIDATE_READY/BEST announcements whose reqtime is in the future (when the clock time went backwards).
struct ByTime {};
using ByTimeView = std::pair<WaitState, std::chrono::microseconds>;
struct ByTimeViewExtractor
{
    using result_type = ByTimeView;
    result_type operator()(const Announcement& ann) const
    {
        return ByTimeView{ann.GetWaitState(), ann.m_time};
    }
};

/** Data type for the main data structure (Announcement objects with ByPeer/ByTxHash/ByTime indexes). */
using Index = boost::multi_index_container<
    Announcement,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::tag<ByPeer>, ByPeerViewExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByTxHash>, ByTxHashViewExtractor>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ByTime>, ByTimeViewExtractor>
    >
>;

/** Helper type to simplify syntax of iterator types. */
template<typename Tag>
using Iter = typename Index::index<Tag>::type::iterator;

/** Per-peer statistics object. */
struct PeerInfo {
    size_t m_total = 0; //!< Total number of announcements for this peer.
    size_t m_completed = 0; //!< Number of COMPLETED announcements for this peer.
    size_t m_requested = 0; //!< Number of REQUESTED announcements for this peer.
    
    /** Compare two PeerInfo objects. Only used for testing. */
    friend bool operator==(const PeerInfo& a, const PeerInfo& b)
    {
        return std::tie(a.m_total, a.m_completed, a.m_requested) ==
               std::tie(b.m_total, b.m_completed, b.m_requested);
    }

};

/** Implementation class for TxRequestTracker's data structure. All members are public
 *  for testing. This file isn't included from anything than txrequest.cpp and the test
 *  files. */
class TxRequestTrackerImpl {
public:
    TxRequestTrackerImpl(bool deterministic = false) :
        m_computer(deterministic),
        // Explicitly initialize m_index as we need to pass a reference to m_computer to ByTxHashViewExtractor.
        m_index(boost::make_tuple(
            boost::make_tuple(ByPeerViewExtractor(), std::less<ByPeerView>()),
            boost::make_tuple(ByTxHashViewExtractor(m_computer), std::less<ByTxHashView>()),
            boost::make_tuple(ByTimeViewExtractor(), std::less<ByTimeView>())
        )) {}

    // Disable copying and assigning (a default copy won't work due the stateful ByTxHashViewExtractor).
    TxRequestTrackerImpl(const TxRequestTrackerImpl&) = delete;
    TxRequestTrackerImpl& operator=(const TxRequestTrackerImpl&) = delete;

    // Public interface functions.

    //* Part of public interface. See TxRequestTracker::DisconnectPeer() */
    void DisconnectedPeer(NodeId peer);
    //* Part of public interface. See TxRequestTracker::ForgetTxHash() */
    void ForgetTxHash(const uint256& txhash);
    //* Part of public interface. See TxRequestTracker::ReceivedInv() */
    void ReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred, std::chrono::microseconds reqtime);
    //* Part of public interface. See TxRequestTracker::GetRequestable() */
    std::vector<GenTxid> GetRequestable(NodeId peer, std::chrono::microseconds now,
        std::vector<std::pair<NodeId, GenTxid>>* expired);
    //* Part of public interface. See TxRequestTracker::RequestedTx() */
    void RequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry);
    //* Part of public interface. See TxRequestTracker::ReceivedResponse() */
    void ReceivedResponse(NodeId peer, const uint256& txhash);
    //* Part of public interface. See TxRequestTracker::CountInFlight() */
    size_t CountInFlight(NodeId peer) const;
    //* Part of public interface. See TxRequestTracker::CountCandidates()() */
    size_t CountCandidates(NodeId peer) const;
    //* Part of public interface. See TxRequestTracker::Count() */
    size_t Count(NodeId peer) const;
    //* Part of public interface. See TxRequestTracker::Size() */
    size_t Size() const;

    // Data members

    //! The current sequence number. Increases for every announcement. This is used to sort txhashes returned by
    //! GetRequestable in announcement order.
    SequenceNumber m_current_sequence{0};
    //! This tracker's priority computer.
    const PriorityComputer m_computer;
    //! This tracker's main data structure.
    Index m_index;
    //! Map with this tracker's per-peer statistics.
    std::unordered_map<NodeId, PeerInfo> m_peerinfo;

    // 'Private' implementation functions

    //! Wrapper around Index::...::erase that keeps m_peerinfo up to date.
    template<typename Tag>
    Iter<Tag> Erase(Iter<Tag> it);

    //! Wrapper around Index::...::modify that keeps m_peerinfo up to date.
    template<typename Tag, typename Modifier>
    void Modify(Iter<Tag> it, Modifier modifier);

    //! Convert a CANDIDATE_DELAYED announcement into a CANDIDATE_READY. If this makes it the new best
    //! CANDIDATE_READY (and no REQUESTED exists) and better than the CANDIDATE_BEST (if any), it becomes the new
    //! CANDIDATE_BEST.
    void PromoteCandidateReady(Iter<ByTxHash> it);

    //! Change the state of an announcement to something non-IsSelected(). If it was IsSelected(), the next best
    //! announcement will be marked CANDIDATE_BEST.
    void ChangeAndReselect(Iter<ByTxHash> it, State new_state);

    //! Check if 'it' is the only announcement for a given txhash that isn't COMPLETED.
    bool IsOnlyNonCompleted(Iter<ByTxHash> it);

    /** Convert any announcement to a COMPLETED one. If there are no non-COMPLETED announcements left for this
     *  txhash, they are deleted. If this was a REQUESTED announcement, and there are other CANDIDATEs left, the
     *  best one is made CANDIDATE_BEST. Returns whether the announcement still exists. */
    bool MakeCompleted(Iter<ByTxHash> it);

    //! Make the data structure consistent with a given point in time:
    //! - REQUESTED annoucements with expiry <= now are turned into COMPLETED.
    //! - CANDIDATE_DELAYED announcements with reqtime <= now are turned into CANDIDATE_{READY,BEST}.
    //! - CANDIDATE_{READY,BEST} announcements with reqtime > now are turned into CANDIDATE_DELAYED.
    void SetTimePoint(std::chrono::microseconds now, std::vector<std::pair<NodeId, GenTxid>>* expired);
};
#endif // BITCOIN_TXREQUEST_IMPL_H
