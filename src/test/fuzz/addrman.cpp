// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrdb.h>
#include <addrman.h>
#include <chainparams.h>
#include <merkleblock.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <time.h>
#include <util/asmap.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

void initialize_addrman()
{
    SelectParams(CBaseChainParams::REGTEST);
}

class CAddrManDeterministic : public CAddrMan
{
public:
    explicit CAddrManDeterministic(FuzzedDataProvider& fuzzed_data_provider)
    {
        insecure_rand = FastRandomContext{ConsumeUInt256(fuzzed_data_provider)};
        if (fuzzed_data_provider.ConsumeBool()) {
            m_asmap = ConsumeRandomLengthBitVector(fuzzed_data_provider);
            if (!SanityCheckASMap(m_asmap)) {
                m_asmap.clear();
            }
        }
    }

    /**
     * Generate a random address.
     */
    CNetAddr RandAddr()
    {
        // The networks [1..6] correspond to CNetAddr::BIP155Network (private).
        static const std::map<uint8_t, uint8_t> net_len_map = {
            {1, ADDR_IPV4_SIZE},  {2, ADDR_IPV6_SIZE}, {3, ADDR_TORV2_SIZE},
            {4, ADDR_TORV3_SIZE}, {5, ADDR_I2P_SIZE},  {6, ADDR_CJDNS_SIZE}};
        const uint8_t net = insecure_rand.randrange(6) + 1; // [1..6]

        CDataStream s(SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);

        s << net;
        s << insecure_rand.randbytes(net_len_map.at(net));

        CNetAddr addr;
        s >> addr;
        return addr;
    }

    /**
     * Fill this addrman with lots of addresses from lots of sources.
     */
    void Fill()
    {
        LOCK(cs);

        // Add some of the addresses directly to the "tried" table.
        const auto n = insecure_rand.randrange(4); // 0, 1, 2, 3 corresponding to 0%, 100%, 50%, 33%

        const size_t num_sources = insecure_rand.randrange(100) + 1; // [1..100]
        for (size_t i = 0; i < num_sources; ++i) {
            const auto source = RandAddr();
            const size_t num_addresses = insecure_rand.randrange(1000) + 1; // [1..1000]

            for (size_t j = 0; j < num_addresses; ++j) {
                const auto addr = CAddress{CService{RandAddr(), 8333}, NODE_NETWORK};
                const auto time_penalty = insecure_rand.randrange(100000001);
                if (n > 0 && mapInfo.size() % n == 0 && mapAddr.find(addr) == mapAddr.end()) {
                    // Add to the "tried" table (if the bucket slot is free).
                    const CAddrInfo dummy{addr, source};
                    const int bucket = dummy.GetTriedBucket(nKey, m_asmap);
                    const int bucket_pos = dummy.GetBucketPosition(nKey, false, bucket);
                    if (vvTried[bucket][bucket_pos] == -1) {
                        int id;
                        CAddrInfo* addr_info = Create(addr, source, &id);
                        vvTried[bucket][bucket_pos] = id;
                        addr_info->fInTried = true;
                        ++nTried;
                    }
                } else {
                    // Add to the "new" table.
                    Add_(addr, source, time_penalty);
                }
            }
        }
    }

    /**
     * Compare with another AddrMan.
     * This compares:
     * - the values in `mapInfo` (the keys aka ids are ignored)
     * - vvNew entries refer to the same addresses
     * - vvTried entries refer to the same addresses
     */
    bool operator==(const CAddrManDeterministic& other)
    {
        LOCK2(cs, other.cs);

        if (mapInfo.size() != other.mapInfo.size() || nNew != other.nNew ||
            nTried != other.nTried) {
            return false;
        }

        // Check that all values in `mapInfo` are equal to all values in `other.mapInfo`.
        // Keys may be different.

        auto GetSortedAddresses = [](std::map<int, CAddrInfo> m) {
            std::vector<CAddrInfo> addresses(m.size());
            size_t i = 0;
            for (const auto& [id, addr] : m) {
                addresses[i++] = addr;
            }
            std::sort(addresses.begin(), addresses.end());
            return addresses;
        };

        const auto& addresses = GetSortedAddresses(mapInfo);
        const auto& other_addresses = GetSortedAddresses(other.mapInfo);

        for (size_t i = 0; i < addresses.size(); ++i) {
            const auto& addr = addresses[i];
            const auto& other_addr = other_addresses.at(i);
            if (addr.source != other_addr.source || addr.nLastSuccess != other_addr.nLastSuccess ||
                addr.nAttempts != other_addr.nAttempts || addr.nRefCount != other_addr.nRefCount ||
                addr.fInTried != other_addr.fInTried) {
                return false;
            }
        }

        auto IdsReferToSameAddress = [&](int id, int other_id) EXCLUSIVE_LOCKS_REQUIRED(cs, other.cs) {
            if (id == -1 && other_id == -1) {
                return true;
            }
            if ((id == -1 && other_id != -1) || (id != -1 && other_id == -1)) {
                return false;
            }
            return mapInfo.at(id) == other.mapInfo.at(other_id);
        };

        // Check that `vvNew` contains the same addresses as `other.vvNew`. Notice - `vvNew[i][j]`
        // contains just an id and the address is to be found in `mapInfo.at(id)`. The ids
        // themselves may differ between `vvNew` and `other.vvNew`.
        for (size_t i = 0; i < ADDRMAN_NEW_BUCKET_COUNT; ++i) {
            for (size_t j = 0; j < ADDRMAN_BUCKET_SIZE; ++j) {
                if (!IdsReferToSameAddress(vvNew[i][j], other.vvNew[i][j])) {
                    return false;
                }
            }
        }

        // Same for `vvTried`.
        for (size_t i = 0; i < ADDRMAN_TRIED_BUCKET_COUNT; ++i) {
            for (size_t j = 0; j < ADDRMAN_BUCKET_SIZE; ++j) {
                if (!IdsReferToSameAddress(vvTried[i][j], other.vvTried[i][j])) {
                    return false;
                }
            }
        }

        return true;
    }
};

FUZZ_TARGET_INIT(addrman, initialize_addrman)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));
    CAddrManDeterministic addr_man{fuzzed_data_provider};
    while (fuzzed_data_provider.ConsumeBool()) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                addr_man.Clear();
            },
            [&] {
                addr_man.ResolveCollisions();
            },
            [&] {
                (void)addr_man.SelectTriedCollision();
            },
            [&] {
                (void)addr_man.Select(fuzzed_data_provider.ConsumeBool());
            },
            [&] {
                (void)addr_man.GetAddr(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096), fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096));
            },
            [&] {
                const std::optional<CAddress> opt_address = ConsumeDeserializable<CAddress>(fuzzed_data_provider);
                const std::optional<CNetAddr> opt_net_addr = ConsumeDeserializable<CNetAddr>(fuzzed_data_provider);
                if (opt_address && opt_net_addr) {
                    addr_man.Add(*opt_address, *opt_net_addr, fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 100000000));
                }
            },
            [&] {
                std::vector<CAddress> addresses;
                while (fuzzed_data_provider.ConsumeBool()) {
                    const std::optional<CAddress> opt_address = ConsumeDeserializable<CAddress>(fuzzed_data_provider);
                    if (!opt_address) {
                        break;
                    }
                    addresses.push_back(*opt_address);
                }
                const std::optional<CNetAddr> opt_net_addr = ConsumeDeserializable<CNetAddr>(fuzzed_data_provider);
                if (opt_net_addr) {
                    addr_man.Add(addresses, *opt_net_addr, fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 100000000));
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    addr_man.Good(*opt_service, fuzzed_data_provider.ConsumeBool(), ConsumeTime(fuzzed_data_provider));
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    addr_man.Attempt(*opt_service, fuzzed_data_provider.ConsumeBool(), ConsumeTime(fuzzed_data_provider));
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    addr_man.Connected(*opt_service, ConsumeTime(fuzzed_data_provider));
                }
            },
            [&] {
                const std::optional<CService> opt_service = ConsumeDeserializable<CService>(fuzzed_data_provider);
                if (opt_service) {
                    addr_man.SetServices(*opt_service, ServiceFlags{fuzzed_data_provider.ConsumeIntegral<uint64_t>()});
                }
            },
            [&] {
                (void)addr_man.Check();
            });
    }
    (void)addr_man.size();
    CDataStream data_stream(SER_NETWORK, PROTOCOL_VERSION);
    data_stream << addr_man;
}

// Check that serialize followed by unserialize produces the same addrman.
FUZZ_TARGET_INIT(addrman_serdeser, initialize_addrman)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    CAddrManDeterministic addr_man1{fuzzed_data_provider};
    CAddrManDeterministic addr_man2{fuzzed_data_provider};
    addr_man2.m_asmap = addr_man1.m_asmap;

    CDataStream data_stream(SER_NETWORK, PROTOCOL_VERSION);

    addr_man1.Fill();
    data_stream << addr_man1;
    data_stream >> addr_man2;
    assert(addr_man1 == addr_man2);
}
