// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <script/standard.h>
#include <univalue.h>
#include <utilstrencodings.h>

#include <boost/variant/static_visitor.hpp>

class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    explicit DescribeAddressVisitor() {}

    UniValue operator()(const CNoDestination &dest) const;
    UniValue operator()(const CKeyID &keyID) const;
    UniValue operator()(const CScriptID &scriptID) const;
    UniValue operator()(const WitnessV0KeyHash& id) const;
    UniValue operator()(const WitnessV0ScriptHash& id) const;
    UniValue operator()(const WitnessUnknown& id) const;
};

