// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletinitinterface.h"

static WalletInitSignals wallet_init_signals;

WalletInitSignals& GetWalletInitSignals()
{
    return wallet_init_signals;
}

void RegisterWalletInitInterface(WalletInitInterface* wallet_interface) {
    wallet_init_signals.GetWalletHelpString.connect(boost::bind(&WalletInitInterface::GetWalletHelpString, wallet_interface, _1));
    wallet_init_signals.WalletParameterInteraction.connect(boost::bind(&WalletInitInterface::WalletParameterInteraction, wallet_interface));
    wallet_init_signals.RegisterWalletRPC.connect(boost::bind(&WalletInitInterface::RegisterWalletRPC, wallet_interface, _1));
    wallet_init_signals.VerifyWallets.connect(boost::bind(&WalletInitInterface::VerifyWallets, wallet_interface));
    wallet_init_signals.OpenWallets.connect(boost::bind(&WalletInitInterface::OpenWallets, wallet_interface));
    wallet_init_signals.StartWallets.connect(boost::bind(&WalletInitInterface::StartWallets, wallet_interface, _1));
    wallet_init_signals.FlushWallets.connect(boost::bind(&WalletInitInterface::FlushWallets, wallet_interface));
    wallet_init_signals.StopWallets.connect(boost::bind(&WalletInitInterface::StopWallets, wallet_interface));
    wallet_init_signals.CloseWallets.connect(boost::bind(&WalletInitInterface::CloseWallets, wallet_interface));
}

void UnregisterWalletInitInterface(WalletInitInterface* pwalletIn) {
    wallet_init_signals.GetWalletHelpString.disconnect(boost::bind(&WalletInitInterface::GetWalletHelpString, pwalletIn, _1));
    wallet_init_signals.WalletParameterInteraction.disconnect(boost::bind(&WalletInitInterface::WalletParameterInteraction, pwalletIn));
    wallet_init_signals.RegisterWalletRPC.disconnect(boost::bind(&WalletInitInterface::RegisterWalletRPC, pwalletIn, _1));
    wallet_init_signals.VerifyWallets.disconnect(boost::bind(&WalletInitInterface::VerifyWallets, pwalletIn));
    wallet_init_signals.OpenWallets.disconnect(boost::bind(&WalletInitInterface::OpenWallets, pwalletIn));
    wallet_init_signals.StartWallets.disconnect(boost::bind(&WalletInitInterface::StartWallets, pwalletIn, _1));
    wallet_init_signals.FlushWallets.disconnect(boost::bind(&WalletInitInterface::FlushWallets, pwalletIn));
    wallet_init_signals.StopWallets.disconnect(boost::bind(&WalletInitInterface::StopWallets, pwalletIn));
    wallet_init_signals.CloseWallets.disconnect(boost::bind(&WalletInitInterface::CloseWallets, pwalletIn));
}

void UnregisterAllWalletInitInterfaces() {
    wallet_init_signals.GetWalletHelpString.disconnect_all_slots();
    wallet_init_signals.WalletParameterInteraction.disconnect_all_slots();
    wallet_init_signals.RegisterWalletRPC.disconnect_all_slots();
    wallet_init_signals.VerifyWallets.disconnect_all_slots();
    wallet_init_signals.OpenWallets.disconnect_all_slots();
    wallet_init_signals.FlushWallets.disconnect_all_slots();
    wallet_init_signals.StopWallets.disconnect_all_slots();
    wallet_init_signals.CloseWallets.disconnect_all_slots();
}
