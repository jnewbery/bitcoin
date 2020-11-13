// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netgroup.h>

#include <netaddress.h>

namespace {
    class NetGrouper
    {
    public:
        uint32_t GetMappedAS(const CNetAddr& addr);
        std::vector<unsigned char> GetGroup(const CNetAddr& addr);
        bool LoadAsmap(fs::path path);
        uint256 GetAsmapVersion();
        
        std::vector<bool> m_asmap;
    } g_netgrouper;
} // unnamed namespace

uint32_t NetGrouper::GetMappedAS(const CNetAddr& addr) {
    uint32_t net_class = addr.GetNetClass();
    if (m_asmap.empty() || (net_class != NET_IPV4 && net_class != NET_IPV6)) {
        return 0; // Indicates not found, safe because AS0 is reserved per RFC7607.
    }
    std::vector<bool> ip_bits(128);
    if (addr.HasLinkedIPv4()) {
        // For lookup, treat as if it was just an IPv4 address (IPV4_IN_IPV6_PREFIX + IPv4 bits)
        for (int8_t byte_i = 0; byte_i < 12; ++byte_i) {
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (IPV4_IN_IPV6_PREFIX[byte_i] >> (7 - bit_i)) & 1;
            }
        }
        uint32_t ipv4 = addr.GetLinkedIPv4();
        for (int i = 0; i < 32; ++i) {
            ip_bits[96 + i] = (ipv4 >> (31 - i)) & 1;
        }
    } else {
        // Use all 128 bits of the IPv6 address otherwise
        assert(addr.IsIPv6());
        for (int8_t byte_i = 0; byte_i < 16; ++byte_i) {
            uint8_t cur_byte = addr.m_addr[byte_i];
            for (uint8_t bit_i = 0; bit_i < 8; ++bit_i) {
                ip_bits[byte_i * 8 + bit_i] = (cur_byte >> (7 - bit_i)) & 1;
            }
        }
    }
    uint32_t mapped_as = Interpret(m_asmap, ip_bits);
    return mapped_as;
}

std::vector<unsigned char> NetGrouper::GetGroup(const CNetAddr& addr)
{
    std::vector<unsigned char> vchRet;
    uint32_t net_class = addr.GetNetClass();
    // If m_asmap is supplied and the address is IPv4/IPv6,
    // return ASN to be used for bucketing.
    uint32_t asn = GetMappedAS(addr);
    if (asn != 0) { // Either m_asmap was empty, or address has non-asmappable net class (e.g. TOR).
        vchRet.push_back(NET_IPV6); // IPv4 and IPv6 with same ASN should be in the same bucket
        for (int i = 0; i < 4; i++) {
            vchRet.push_back((asn >> (8 * i)) & 0xFF);
        }
        return vchRet;
    }

    vchRet.push_back(net_class);
    int nBits{0};

    if (addr.IsLocal()) {
        // all local addresses belong to the same group
    } else if (addr.IsInternal()) {
        // all internal-usage addresses get their own group
        nBits = ADDR_INTERNAL_SIZE * 8;
    } else if (!addr.IsRoutable()) {
        // all other unroutable addresses belong to the same group
    } else if (addr.HasLinkedIPv4()) {
        // IPv4 addresses (and mapped IPv4 addresses) use /16 groups
        uint32_t ipv4 = addr.GetLinkedIPv4();
        vchRet.push_back((ipv4 >> 24) & 0xFF);
        vchRet.push_back((ipv4 >> 16) & 0xFF);
        return vchRet;
    } else if (addr.IsTor() || addr.IsI2P() || addr.IsCJDNS()) {
        nBits = 4;
    } else if (addr.IsHeNet()) {
        // for he.net, use /36 groups
        nBits = 36;
    } else {
        // for the rest of the IPv6 network, use /32 groups
        nBits = 32;
    }

    // Push the address onto vchRet.
    const size_t num_bytes = nBits / 8;
    vchRet.insert(vchRet.end(), addr.m_addr.begin(), addr.m_addr.begin() + num_bytes);
    nBits %= 8;
    // ...for the last byte, push nBits and for the rest of the byte push 1's
    if (nBits > 0) {
        assert(num_bytes < addr_bytes.size());
        vchRet.push_back(addr_bytes[num_bytes] | ((1 << (8 - nBits)) - 1));
    }

    return vchRet;
}

bool NetGrouper::LoadAsmap(fs::path path)
{
    FILE *filestr = fsbridge::fopen(path, "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open asmap file from disk\n");
        return false;
    }
    fseek(filestr, 0, SEEK_END);
    int length = ftell(filestr);
    LogPrintf("Opened asmap file %s (%d bytes) from disk\n", path, length);
    fseek(filestr, 0, SEEK_SET);
    char cur_byte;
    for (int i = 0; i < length; ++i) {
        file >> cur_byte;
        for (int bit = 0; bit < 8; ++bit) {
            m_asmap.push_back((cur_byte >> bit) & 1);
        }
    }
    if (!SanityCheckASMap(m_asmap)) {
        LogPrintf("Sanity check of asmap file %s failed\n", path);
        return {};
    }
    const uint256 asmap_version{SerializeHash(asmap)};
    LogPrintf("Using asmap version %s for IP bucketing\n", asmap_version.ToString());
    return true;
}

uint256 NetGrouper::GetAsmapVersion()
{
    if (m_asmap.empty) return {};
    return SerializeHash(m_asmap);
}

uint32_t GetMappedAS(const CNetAddr& addr) { g_netgrouper.GetMappedAS(addr) }
std::vector<unsigned char> GetGroup(const CNetAddr& addr) { g_netgrouper.GetGroup(addr) }
bool NetGrouper::LoadAsmap(fs::path path) { g_netgrouper.LoadAsmap(path) }
uint256 NetGrouper::GetAsmapVersion() { g_netgrouper.GetAsmapVersion() }
