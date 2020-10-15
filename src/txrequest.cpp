// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txrequest.h>
#include <txrequest_impl.h>

#include <crypto/siphash.h>
#include <net.h>
#include <primitives/transaction.h>
#include <random.h>
#include <uint256.h>
#include <util/memory.h>

#include <utility>

#include <assert.h>

namespace {

/** Per-txhash statistics object. Only used for sanity checking. */
struct TxHashInfo
{
    //! Number of CANDIDATE_DELAYED announcements for this txhash.
    size_t m_candidate_delayed = 0;
    //! Number of CANDIDATE_READY announcements for this txhash.
    size_t m_candidate_ready = 0;
    //! Number of CANDIDATE_BEST announcements for this txhash (at most one).
    size_t m_candidate_best = 0;
    //! Number of REQUESTED announcements for this txhash (at most one; mutually exclusive with CANDIDATE_BEST).
    size_t m_requested = 0;
    //! The priority of the CANDIDATE_BEST announcement if one exists, or max() otherwise.
    Priority m_priority_candidate_best = std::numeric_limits<Priority>::max();
    //! The highest priority of all CANDIDATE_READY announcements (or min() if none exist).
    Priority m_priority_best_candidate_ready = std::numeric_limits<Priority>::min();
    //! All peers we have an announcement for this txhash for.
    std::vector<NodeId> m_peers;
};

/** (Re)compute the PeerInfo map from the index. Only used for sanity checking. */
std::unordered_map<NodeId, PeerInfo> RecomputePeerInfo(const Index& index)
{
    std::unordered_map<NodeId, PeerInfo> ret;
    for (const Announcement& ann : index) {
        PeerInfo& info = ret[ann.m_peer];
        ++info.m_total;
        info.m_requested += (ann.m_state == State::REQUESTED);
        info.m_completed += (ann.m_state == State::COMPLETED);
    }
    return ret;
}

/** Compute the TxHashInfo map. Only used for sanity checking. */
std::map<uint256, TxHashInfo> ComputeTxHashInfo(const Index& index, const PriorityComputer& computer)
{
    std::map<uint256, TxHashInfo> ret;
    for (const Announcement& ann : index) {
        TxHashInfo& info = ret[ann.m_txhash];
        // Classify how many announcements of each state we have for this txhash.
        info.m_candidate_delayed += (ann.m_state == State::CANDIDATE_DELAYED);
        info.m_candidate_ready += (ann.m_state == State::CANDIDATE_READY);
        info.m_candidate_best += (ann.m_state == State::CANDIDATE_BEST);
        info.m_requested += (ann.m_state == State::REQUESTED);
        // And track the priority of the best CANDIDATE_READY/CANDIDATE_BEST announcements.
        if (ann.m_state == State::CANDIDATE_BEST) {
            info.m_priority_candidate_best = computer(ann);
        }
        if (ann.m_state == State::CANDIDATE_READY) {
            info.m_priority_best_candidate_ready = std::max(info.m_priority_best_candidate_ready, computer(ann));
        }
        // Also keep track of which peers this txhash has an announcement for (so we can detect duplicates).
        info.m_peers.push_back(ann.m_peer);
    }
    return ret;
}

GenTxid ToGenTxid(const Announcement& ann)
{
    return {ann.m_is_wtxid, ann.m_txhash};
}

}  // namespace

WaitState GetWaitState(const Announcement& ann)
{
    if (ann.IsWaiting()) return WaitState::FUTURE_EVENT;
    if (ann.IsSelectable()) return WaitState::PAST_EVENT;
    return WaitState::NO_EVENT;
}

bool operator==(const PeerInfo& a, const PeerInfo& b)
{
    return std::tie(a.m_total, a.m_completed, a.m_requested) ==
           std::tie(b.m_total, b.m_completed, b.m_requested);
}

/** Actual implementation for TxRequestTracker's data structure. */
void TxRequestTrackerImpl::SanityCheck() const
{
    // Recompute m_peerdata from m_index. This verifies the data in it as it should just be caching statistics
    // on m_index. It also verifies the invariant that no PeerInfo announcements with m_total==0 exist.
    assert(m_peerinfo == RecomputePeerInfo(m_index));

    // Calculate per-txhash statistics from m_index, and validate invariants.
    for (auto& item : ComputeTxHashInfo(m_index, m_computer)) {
        TxHashInfo& info = item.second;

        // Cannot have only COMPLETED peer (txhash should have been forgotten already)
        assert(info.m_candidate_delayed + info.m_candidate_ready + info.m_candidate_best + info.m_requested > 0);

        // Can have at most 1 CANDIDATE_BEST/REQUESTED peer
        assert(info.m_candidate_best + info.m_requested <= 1);

        // If there are any CANDIDATE_READY announcements, there must be exactly one CANDIDATE_BEST or REQUESTED
        // announcement.
        if (info.m_candidate_ready > 0) {
            assert(info.m_candidate_best + info.m_requested == 1);
        }

        // If there is both a CANDIDATE_READY and a CANDIDATE_BEST announcement, the CANDIDATE_BEST one must be
        // at least as good (equal or higher priority) as the best CANDIDATE_READY.
        if (info.m_candidate_ready && info.m_candidate_best) {
            assert(info.m_priority_candidate_best >= info.m_priority_best_candidate_ready);
        }

        // No txhash can have been announced by the same peer twice.
        std::sort(info.m_peers.begin(), info.m_peers.end());
        assert(std::adjacent_find(info.m_peers.begin(), info.m_peers.end()) == info.m_peers.end());
    }
}

void TxRequestTrackerImpl::PostGetRequestableSanityCheck(std::chrono::microseconds now) const
{
    for (const Announcement& ann : m_index) {
        if (ann.IsWaiting()) {
            // REQUESTED and CANDIDATE_DELAYED must have a time in the future (they should have been converted
            // to COMPLETED/CANDIDATE_READY respectively).
            assert(ann.m_time > now);
        } else if (ann.IsSelectable()) {
            // CANDIDATE_READY and CANDIDATE_BEST cannot have a time in the future (they should have remained
            // CANDIDATE_DELAYED, or should have been converted back to it if time went backwards).
            assert(ann.m_time <= now);
        }
    }
}

//! Wrapper around Index::...::erase that keeps m_peerinfo up to date.
template<typename Tag>
Iter<Tag> TxRequestTrackerImpl::Erase(Iter<Tag> it)
{
    auto peerit = m_peerinfo.find(it->m_peer);
    peerit->second.m_completed -= it->m_state == State::COMPLETED;
    peerit->second.m_requested -= it->m_state == State::REQUESTED;
    if (--peerit->second.m_total == 0) m_peerinfo.erase(peerit);
    return m_index.get<Tag>().erase(it);
}

//! Wrapper around Index::...::modify that keeps m_peerinfo up to date.
template<typename Tag, typename Modifier>
void TxRequestTrackerImpl::Modify(Iter<Tag> it, Modifier modifier)
{
    auto peerit = m_peerinfo.find(it->m_peer);
    peerit->second.m_completed -= it->m_state == State::COMPLETED;
    peerit->second.m_requested -= it->m_state == State::REQUESTED;
    m_index.get<Tag>().modify(it, std::move(modifier));
    peerit->second.m_completed += it->m_state == State::COMPLETED;
    peerit->second.m_requested += it->m_state == State::REQUESTED;
}

//! Convert a CANDIDATE_DELAYED announcement into a CANDIDATE_READY. If this makes it the new best
//! CANDIDATE_READY (and no REQUESTED exists) and better than the CANDIDATE_BEST (if any), it becomes the new
//! CANDIDATE_BEST.
void TxRequestTrackerImpl::PromoteCandidateReady(Iter<ByTxHash> it)
{
    assert(it != m_index.get<ByTxHash>().end());
    assert(it->m_state == State::CANDIDATE_DELAYED);
    // Convert CANDIDATE_DELAYED to CANDIDATE_READY first.
    Modify<ByTxHash>(it, [](Announcement& ann){ ann.m_state = State::CANDIDATE_READY; });
    // The following code relies on the fact that the ByTxHash is sorted by txhash, and then by state (first
    // _DELAYED, then _READY, then _BEST/REQUESTED). Within the _READY announcements, the best one (highest
    // priority) comes last. Thus, if an existing _BEST exists for the same txhash that this announcement may
    // be preferred over, it must immediately follow the newly created _READY.
    auto it_next = std::next(it);
    if (it_next == m_index.get<ByTxHash>().end() || it_next->m_txhash != it->m_txhash ||
        it_next->m_state == State::COMPLETED) {
        // This is the new best CANDIDATE_READY, and there is no IsSelected() announcement for this txhash
        // already.
        Modify<ByTxHash>(it, [](Announcement& ann){ ann.m_state = State::CANDIDATE_BEST; });
    } else if (it_next->m_state == State::CANDIDATE_BEST) {
        Priority priority_old = m_computer(*it_next);
        Priority priority_new = m_computer(*it);
        if (priority_new > priority_old) {
            // There is a CANDIDATE_BEST announcement already, but this one is better.
            Modify<ByTxHash>(it_next, [](Announcement& ann){ ann.m_state = State::CANDIDATE_READY; });
            Modify<ByTxHash>(it, [](Announcement& ann){ ann.m_state = State::CANDIDATE_BEST; });
        }
    }
}

//! Change the state of an announcement to something non-IsSelected(). If it was IsSelected(), the next best
//! announcement will be marked CANDIDATE_BEST.
void TxRequestTrackerImpl::ChangeAndReselect(Iter<ByTxHash> it, State new_state)
{
    assert(new_state == State::COMPLETED || new_state == State::CANDIDATE_DELAYED);
    assert(it != m_index.get<ByTxHash>().end());
    if (it->IsSelected() && it != m_index.get<ByTxHash>().begin()) {
        auto it_prev = std::prev(it);
        // The next best CANDIDATE_READY, if any, immediately precedes the REQUESTED or CANDIDATE_BEST
        // announcement in the ByTxHash index.
        if (it_prev->m_txhash == it->m_txhash && it_prev->m_state == State::CANDIDATE_READY) {
            // If one such CANDIDATE_READY exists (for this txhash), convert it to CANDIDATE_BEST.
            Modify<ByTxHash>(it_prev, [](Announcement& ann){ ann.m_state = State::CANDIDATE_BEST; });
        }
    }
    Modify<ByTxHash>(it, [new_state](Announcement& ann){ ann.m_state = new_state; });
}

//! Check if 'it' is the only announcement for a given txhash that isn't COMPLETED.
bool TxRequestTrackerImpl::IsOnlyNonCompleted(Iter<ByTxHash> it)
{
    assert(it != m_index.get<ByTxHash>().end());
    assert(it->m_state != State::COMPLETED); // Not allowed to call this on COMPLETED announcements.

    // This announcement has a predecessor that belongs to the same txhash. Due to ordering, and the
    // fact that 'it' is not COMPLETED, its predecessor cannot be COMPLETED here.
    if (it != m_index.get<ByTxHash>().begin() && std::prev(it)->m_txhash == it->m_txhash) return false;

    // This announcement has a successor that belongs to the same txhash, and is not COMPLETED.
    if (std::next(it) != m_index.get<ByTxHash>().end() && std::next(it)->m_txhash == it->m_txhash &&
        std::next(it)->m_state != State::COMPLETED) return false;

    return true;
}

/** Convert any announcement to a COMPLETED one. If there are no non-COMPLETED announcements left for this
 *  txhash, they are deleted. If this was a REQUESTED announcement, and there are other CANDIDATEs left, the
 *  best one is made CANDIDATE_BEST. Returns whether the announcement still exists. */
bool TxRequestTrackerImpl::MakeCompleted(Iter<ByTxHash> it)
{
    assert(it != m_index.get<ByTxHash>().end());

    // Nothing to be done if it's already COMPLETED.
    if (it->m_state == State::COMPLETED) return true;

    if (IsOnlyNonCompleted(it)) {
        // This is the last non-COMPLETED announcement for this txhash. Delete all.
        uint256 txhash = it->m_txhash;
        do {
            it = Erase<ByTxHash>(it);
        } while (it != m_index.get<ByTxHash>().end() && it->m_txhash == txhash);
        return false;
    }

    // Mark the announcement COMPLETED, and select the next best announcement (the first CANDIDATE_READY) if
    // needed.
    ChangeAndReselect(it, State::COMPLETED);

    return true;
}

//! Make the data structure consistent with a given point in time:
//! - REQUESTED annoucements with expiry <= now are turned into COMPLETED.
//! - CANDIDATE_DELAYED announcements with reqtime <= now are turned into CANDIDATE_{READY,BEST}.
//! - CANDIDATE_{READY,BEST} announcements with reqtime > now are turned into CANDIDATE_DELAYED.
void TxRequestTrackerImpl::SetTimePoint(std::chrono::microseconds now, std::vector<std::pair<NodeId, GenTxid>>* expired)
{
    if (expired) expired->clear();

    // Iterate over all CANDIDATE_DELAYED and REQUESTED from old to new, as long as they're in the past,
    // and convert them to CANDIDATE_READY and COMPLETED respectively.
    while (!m_index.empty()) {
        auto it = m_index.get<ByTime>().begin();
        if (it->m_state == State::CANDIDATE_DELAYED && it->m_time <= now) {
            PromoteCandidateReady(m_index.project<ByTxHash>(it));
        } else if (it->m_state == State::REQUESTED && it->m_time <= now) {
            if (expired) expired->emplace_back(it->m_peer, ToGenTxid(*it));
            MakeCompleted(m_index.project<ByTxHash>(it));
        } else {
            break;
        }
    }

    while (!m_index.empty()) {
        // If time went backwards, we may need to demote CANDIDATE_BEST and CANDIDATE_READY announcements back
        // to CANDIDATE_DELAYED. This is an unusual edge case, and unlikely to matter in production. However,
        // it makes it much easier to specify and test TxRequestTrackerImpl's behaviour.
        auto it = std::prev(m_index.get<ByTime>().end());
        if (it->IsSelectable() && it->m_time > now) {
            ChangeAndReselect(m_index.project<ByTxHash>(it), State::CANDIDATE_DELAYED);
        } else {
            break;
        }
    }
}

void TxRequestTrackerImpl::DisconnectedPeer(NodeId peer)
{
    auto& index = m_index.get<ByPeer>();
    auto it = index.lower_bound(ByPeerView{peer, false, uint256::ZERO});
    while (it != index.end() && it->m_peer == peer) {
        // Check what to continue with after this iteration. 'it' will be deleted in what follows, so we need to
        // decide what to continue with afterwards. There are a number of cases to consider:
        // - std::next(it) is end() or belongs to a different peer. In that case, this is the last iteration
        //   of the loop (denote this by setting it_next to end()).
        // - 'it' is not the only non-COMPLETED announcement for its txhash. This means it will be deleted, but
        //   no other Announcement objects will be modified. Continue with std::next(it) if it belongs to the
        //   same peer, but decide this ahead of time (as 'it' may change position in what follows).
        // - 'it' is the only non-COMPLETED announcement for its txhash. This means it will be deleted along
        //   with all other announcements for the same txhash - which may include std::next(it). However, other
        //   than 'it', no announcements for the same peer can be affected (due to (peer, txhash) uniqueness).
        //   In other words, the situation where std::next(it) is deleted can only occur if std::next(it)
        //   belongs to a different peer but the same txhash as 'it'. This is covered by the first bulletpoint
        //   already, and we'll have set it_next to end().
        auto it_next = (std::next(it) == index.end() || std::next(it)->m_peer != peer) ? index.end() :
            std::next(it);
        // If the announcement isn't already COMPLETED, first make it COMPLETED (which will mark other
        // CANDIDATEs as CANDIDATE_BEST, or delete all of a txhash's announcements if no non-COMPLETED ones are
        // left).
        if (MakeCompleted(m_index.project<ByTxHash>(it))) {
            // Then actually delete the announcement (unless it was already deleted by MakeCompleted).
            Erase<ByPeer>(it);
        }
        it = it_next;
    }
}

void TxRequestTrackerImpl::ForgetTxHash(const uint256& txhash)
{
    auto it = m_index.get<ByTxHash>().lower_bound(ByTxHashView{txhash, State::CANDIDATE_DELAYED, 0});
    while (it != m_index.get<ByTxHash>().end() && it->m_txhash == txhash) {
        it = Erase<ByTxHash>(it);
    }
}

void TxRequestTrackerImpl::ReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred,
    std::chrono::microseconds reqtime)
{
    // Bail out if we already have a CANDIDATE_BEST announcement for this (txhash, peer) combination. The case
    // where there is a non-CANDIDATE_BEST announcement already will be caught by the uniqueness property of the
    // ByPeer index when we try to emplace the new object below.
    if (m_index.get<ByPeer>().count(ByPeerView{peer, true, gtxid.GetHash()})) return;

    // Try creating the announcement with CANDIDATE_DELAYED state (which will fail due to the uniqueness
    // of the ByPeer index if a non-CANDIDATE_BEST announcement already exists with the same txhash and peer).
    // Bail out in that case.
    auto ret = m_index.get<ByPeer>().emplace(gtxid, peer, preferred, reqtime, m_current_sequence);
    if (!ret.second) return;

    // Update accounting metadata.
    ++m_peerinfo[peer].m_total;
    ++m_current_sequence;
}

//! Find the GenTxids to request now from peer.
std::vector<GenTxid> TxRequestTrackerImpl::GetRequestable(NodeId peer, std::chrono::microseconds now,
    std::vector<std::pair<NodeId, GenTxid>>* expired)
{
    // Move time.
    SetTimePoint(now, expired);

    // Find all CANDIDATE_BEST announcements for this peer.
    std::vector<const Announcement*> selected;
    auto it_peer = m_index.get<ByPeer>().lower_bound(ByPeerView{peer, true, uint256::ZERO});
    while (it_peer != m_index.get<ByPeer>().end() && it_peer->m_peer == peer &&
        it_peer->m_state == State::CANDIDATE_BEST) {
        selected.emplace_back(&*it_peer);
        ++it_peer;
    }

    // Sort by sequence number.
    std::sort(selected.begin(), selected.end(), [](const Announcement* a, const Announcement* b) {
        return a->m_sequence < b->m_sequence;
    });

    // Convert to GenTxid and return.
    std::vector<GenTxid> ret;
    ret.reserve(selected.size());
    std::transform(selected.begin(), selected.end(), std::back_inserter(ret), [](const Announcement* ann) {
        return ToGenTxid(*ann);
    });
    return ret;
}

void TxRequestTrackerImpl::RequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
{
    auto it = m_index.get<ByPeer>().find(ByPeerView{peer, true, txhash});
    if (it == m_index.get<ByPeer>().end()) {
        // There is no CANDIDATE_BEST announcement, look for a _READY or _DELAYED instead. If the caller only
        // ever invokes RequestedTx with the values returned by GetRequestable, and no other non-const functions
        // other than ForgetTxHash and GetRequestable in between, this branch will never execute (as txhashes
        // returned by GetRequestable always correspond to CANDIDATE_BEST announcements).

        it = m_index.get<ByPeer>().find(ByPeerView{peer, false, txhash});
        if (it == m_index.get<ByPeer>().end() || (it->m_state != State::CANDIDATE_DELAYED &&
            it->m_state != State::CANDIDATE_READY)) {
            // There is no CANDIDATE announcement tracked for this peer, so we have nothing to do. Either this
            // txhash wasn't tracked at all (and the caller should have called ReceivedInv), or it was already
            // requested and/or completed for other reasons and this is just a superfluous RequestedTx call.
            return;
        }

        // Look for an existing CANDIDATE_BEST or REQUESTED with the same txhash. We only need to do this if the
        // found announcement had a different state than CANDIDATE_BEST. If it did, invariants guarantee that no
        // other CANDIDATE_BEST or REQUESTED can exist.
        auto it_old = m_index.get<ByTxHash>().lower_bound(ByTxHashView{txhash, State::CANDIDATE_BEST, 0});
        if (it_old != m_index.get<ByTxHash>().end() && it_old->m_txhash == txhash) {
            if (it_old->m_state == State::CANDIDATE_BEST) {
                // The data structure's invariants require that there can be at most one CANDIDATE_BEST or one
                // REQUESTED announcement per txhash (but not both simultaneously), so we have to convert any
                // existing CANDIDATE_BEST to another CANDIDATE_* when constructing another REQUESTED.
                // It doesn't matter whether we pick CANDIDATE_READY or _DELAYED here, as SetTimePoint()
                // will correct it at GetRequestable() time. If time only goes forward, it will always be
                // _READY, so pick that to avoid extra work in SetTimePoint().
                Modify<ByTxHash>(it_old, [](Announcement& ann) { ann.m_state = State::CANDIDATE_READY; });
            } else if (it_old->m_state == State::REQUESTED) {
                // As we're no longer waiting for a response to the previous REQUESTED announcement, convert it
                // to COMPLETED. This also helps guaranteeing progress.
                Modify<ByTxHash>(it_old, [](Announcement& ann) { ann.m_state = State::COMPLETED; });
            }
        }
    }

    Modify<ByPeer>(it, [expiry](Announcement& ann) {
        ann.m_state = State::REQUESTED;
        ann.m_time = expiry;
    });
}

void TxRequestTrackerImpl::ReceivedResponse(NodeId peer, const uint256& txhash)
{
    // We need to search the ByPeer index for both (peer, false, txhash) and (peer, true, txhash).
    auto it = m_index.get<ByPeer>().find(ByPeerView{peer, false, txhash});
    if (it == m_index.get<ByPeer>().end()) {
        it = m_index.get<ByPeer>().find(ByPeerView{peer, true, txhash});
    }
    if (it != m_index.get<ByPeer>().end()) MakeCompleted(m_index.project<ByTxHash>(it));
}

size_t TxRequestTrackerImpl::CountInFlight(NodeId peer) const
{
    auto it = m_peerinfo.find(peer);
    if (it != m_peerinfo.end()) return it->second.m_requested;
    return 0;
}

size_t TxRequestTrackerImpl::CountCandidates(NodeId peer) const
{
    auto it = m_peerinfo.find(peer);
    if (it != m_peerinfo.end()) return it->second.m_total - it->second.m_requested - it->second.m_completed;
    return 0;
}

size_t TxRequestTrackerImpl::Count(NodeId peer) const
{
    auto it = m_peerinfo.find(peer);
    if (it != m_peerinfo.end()) return it->second.m_total;
    return 0;
}

//! Count how many announcements are being tracked in total across all peers and transactions.
size_t TxRequestTrackerImpl::Size() const { return m_index.size(); }

uint64_t TxRequestTrackerImpl::ComputePriority(const uint256& txhash, NodeId peer, bool preferred) const
{
    // Return Priority as a uint64_t as Priority is internal.
    return uint64_t{m_computer(txhash, peer, preferred)};
}

TxRequestTracker::TxRequestTracker(bool deterministic) :
    m_impl{MakeUnique<TxRequestTrackerImpl>(deterministic)} {}

TxRequestTracker::~TxRequestTracker() = default;

void TxRequestTracker::ForgetTxHash(const uint256& txhash) { m_impl->ForgetTxHash(txhash); }
void TxRequestTracker::DisconnectedPeer(NodeId peer) { m_impl->DisconnectedPeer(peer); }
size_t TxRequestTracker::CountInFlight(NodeId peer) const { return m_impl->CountInFlight(peer); }
size_t TxRequestTracker::CountCandidates(NodeId peer) const { return m_impl->CountCandidates(peer); }
size_t TxRequestTracker::Count(NodeId peer) const { return m_impl->Count(peer); }
size_t TxRequestTracker::Size() const { return m_impl->Size(); }
void TxRequestTracker::SanityCheck() const { m_impl->SanityCheck(); }

void TxRequestTracker::PostGetRequestableSanityCheck(std::chrono::microseconds now) const
{
    m_impl->PostGetRequestableSanityCheck(now);
}

void TxRequestTracker::ReceivedInv(NodeId peer, const GenTxid& gtxid, bool preferred,
    std::chrono::microseconds reqtime)
{
    m_impl->ReceivedInv(peer, gtxid, preferred, reqtime);
}

void TxRequestTracker::RequestedTx(NodeId peer, const uint256& txhash, std::chrono::microseconds expiry)
{
    m_impl->RequestedTx(peer, txhash, expiry);
}

void TxRequestTracker::ReceivedResponse(NodeId peer, const uint256& txhash)
{
    m_impl->ReceivedResponse(peer, txhash);
}

std::vector<GenTxid> TxRequestTracker::GetRequestable(NodeId peer, std::chrono::microseconds now,
    std::vector<std::pair<NodeId, GenTxid>>* expired)
{
    return m_impl->GetRequestable(peer, now, expired);
}

uint64_t TxRequestTracker::ComputePriority(const uint256& txhash, NodeId peer, bool preferred) const
{
    return m_impl->ComputePriority(txhash, peer, preferred);
}
