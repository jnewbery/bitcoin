// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETGROUP_H
#define BITCOIN_NETGROUP_H

#include <fs.h>
#include <netaddress.h>
#include <streams.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

/** Get which Autonomous system this address belongs to, according to our AS map. */
uint32_t GetMappedAS(const CNetAddr& addr);

/**
 * Get the canonical identifier of an address's network group
 *
 * The groups are assigned in a way where it should be costly for an attacker to
 * obtain addresses with many different group identifiers, even if it is cheap
 * to obtain addresses with the same identifier.
 *
 * @note No two connections will be attempted to addresses with the same network
 *       group.
 */
std::vector<unsigned char> GetGroup(const CNetAddr& addr);

/** Load asmap from provided binary file. */
bool LoadAsmap(fs::path path);

/** Get the version of the AS map that is being used. */
uint256 GetAsmapVersion();
    
#endif // BITCOIN_NETGROUP_H
