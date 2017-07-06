// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_INIT_H
#define BITCOIN_WALLET_INIT_H

#include "walletinitinterface.h"

#include <string>

class CRPCTable;
class CScheduler;

class WalletInit : public WalletInitInterface
{
protected:

    //! Return the wallets help message.
    std::string GetWalletHelpString(bool showDebug);

    //! Wallets parameter interaction
    bool WalletParameterInteraction();

    //! Register wallet RPCs.
    void RegisterWalletRPC(CRPCTable &tableRPC);

    //! Responsible for reading and validating the -wallet arguments and verifying the wallet database.
    bool VerifyWallets();

    //! Load wallet databases.
    bool OpenWallets();

    //! Complete startup of wallets.
    void StartWallets(CScheduler& scheduler);

    //! Flush all wallets in preparation for shutdown.
    void FlushWallets();

    //! Stop all wallets. Wallets will be flushed first.
    void StopWallets();

    //! Close all wallets.
    void CloseWallets();
};

#endif // BITCOIN_WALLET_INIT_H
