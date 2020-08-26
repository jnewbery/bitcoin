// Copyright (c) 2012-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

//! Initial proto version, to be increased after version/verack negotiation
constexpr int INIT_PROTO_VERSION{0};

//! "getheaders" message starts from this version
//! Disconnect immediately from peers that don't support "getheaders" messages
constexpr int MIN_PEER_PROTO_VERSION{31800};

//! BIP31 "pong" messages start from this version
constexpr int BIP0031_VERSION{60000};

//! BIP130 "sendheaders" message and announcing blocks with headers starts with this version
constexpr int SENDHEADERS_VERSION{70012};

//! BIP133 "feefilter" tells peers to filter invs to you by fee starts with this version
constexpr int FEEFILTER_VERSION{70013};

//! BIP152 compact blocks support starts with this version
constexpr int COMPACT_BLOCKS_VERSION{70014};

//! Not banning for invalid compact blocks starts with this version (see BIP152)
constexpr int INVALID_CB_NO_BAN_VERSION{70015};

//! BIP339 "wtxidrelay" command for wtxid-based relay starts with this version
constexpr int WTXID_RELAY_VERSION{70016};

//! Highest p2p protocol version supported by this software
constexpr int PROTOCOL_VERSION{WTXID_RELAY_VERSION};

// Make sure that none of the values above collide with
// `SERIALIZE_TRANSACTION_NO_WITNESS` or `ADDRV2_FORMAT`.

#endif // BITCOIN_VERSION_H
