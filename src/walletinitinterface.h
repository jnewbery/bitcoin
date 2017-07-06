// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WALLETINITINTERFACE_H
#define WALLETINITINTERFACE_H

#include <boost/signals2/signal.hpp>

class CScheduler;
class CRPCTable;
class WalletInitInterface;

/** Register a wallet initialization/shutdown interface from bitcoin_server*/
void RegisterWalletInitInterface(WalletInitInterface* wallet_interface);
/** unregister a wallet initialization/shutdown interface from bitcoin_server*/
void UnregisterWalletInitInterface(WalletInitInterface* wallet_interface);
/** unregister all wallet initialization/shutdown interfaces from bitcoin_server*/
void UnregisterAllWalletInitInterfaces();

class WalletInitInterface {
protected:
    virtual std::string GetWalletHelpString(bool showDebug) {return (std::string)"";}
    virtual bool WalletParameterInteraction() {return false;}
    virtual void RegisterWalletRPC(CRPCTable &) {}
    virtual bool VerifyWallets() {return false;}
    virtual bool OpenWallets() {return false;}
    virtual void StartWallets(CScheduler& scheduler) {}
    virtual void FlushWallets() {}
    virtual void StopWallets() {}
    virtual void CloseWallets() {}
    friend void ::RegisterWalletInitInterface(WalletInitInterface*);
    friend void ::UnregisterWalletInitInterface(WalletInitInterface*);
    friend void ::UnregisterAllWalletInitInterfaces();
};

struct WalletInitSignals {
    /** Callback to get wallet help string */
    boost::signals2::signal<std::string (bool showDebug)> GetWalletHelpString;
    /** Callback to check wallet parameter interaction */
    boost::signals2::signal<bool (void)> WalletParameterInteraction;
    /** Callback to register wallet RPC*/
    boost::signals2::signal<void (CRPCTable& t)> RegisterWalletRPC;
    /** Callback to verify wallets */
    boost::signals2::signal<bool (void)> VerifyWallets;
    /** Callback to open wallets*/
    boost::signals2::signal<bool (void)> OpenWallets;
    /** Callback to start wallets*/
    boost::signals2::signal<void (CScheduler& scheduler)> StartWallets;
    /** Callback to flush Wallets*/
    boost::signals2::signal<void (void)> FlushWallets;
    /** Callback to stop Wallets*/
    boost::signals2::signal<void (void)> StopWallets;
    /** Callback to close wallets */
    boost::signals2::signal<void (void)> CloseWallets;
};

WalletInitSignals& GetWalletInitSignals();

#endif // WALLETINITINTERFACE_H
