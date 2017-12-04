// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <rpc/util.h>
#include <utilstrencodings.h>

UniValue DescribeAddressVisitor::operator()(const CNoDestination &dest) const {
    return UniValue(UniValue::VOBJ);
}

UniValue DescribeAddressVisitor::operator()(const CKeyID &keyID) const {
    UniValue obj(UniValue::VOBJ);
    CPubKey vchPubKey;
    obj.push_back(Pair("isscript", false));
    obj.push_back(Pair("iswitness", false));
    return obj;
}

UniValue DescribeAddressVisitor::operator()(const CScriptID &scriptID) const {
    UniValue obj(UniValue::VOBJ);
    CScript subscript;
    obj.push_back(Pair("isscript", true));
    obj.push_back(Pair("iswitness", false));
    return obj;
}

UniValue DescribeAddressVisitor::operator()(const WitnessV0KeyHash& id) const
{
    UniValue obj(UniValue::VOBJ);
    CPubKey pubkey;
    obj.push_back(Pair("isscript", false));
    obj.push_back(Pair("iswitness", true));
    obj.push_back(Pair("witness_version", 0));
    obj.push_back(Pair("witness_program", HexStr(id.begin(), id.end())));
    return obj;
}

UniValue DescribeAddressVisitor::operator()(const WitnessV0ScriptHash& id) const
{
    UniValue obj(UniValue::VOBJ);
    CScript subscript;
    obj.push_back(Pair("isscript", true));
    obj.push_back(Pair("iswitness", true));
    obj.push_back(Pair("witness_version", 0));
    obj.push_back(Pair("witness_program", HexStr(id.begin(), id.end())));
    return obj;
}

UniValue DescribeAddressVisitor::operator()(const WitnessUnknown& id) const
{
    UniValue obj(UniValue::VOBJ);
    CScript subscript;
    obj.push_back(Pair("iswitness", true));
    obj.push_back(Pair("witness_version", (int)id.version));
    obj.push_back(Pair("witness_program", HexStr(id.program, id.program + id.length)));
    return obj;
}
