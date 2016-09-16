// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <fs.h>
#include <util.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

namespace WalletTool {

static std::shared_ptr<CWallet> CreateWallet(const std::string name, const fs::path& path)
{
    if (fs::exists(path))
    {
        fprintf(stderr, "Error: File exists already\n");
        return NULL;
    }
    std::shared_ptr<CWallet> wallet_instance(new CWallet(name, WalletDatabase::Create(path)), ReleaseWallet);
    bool first_run = true;
    DBErrors load_wallet_ret = wallet_instance->LoadWallet(first_run);
    if (load_wallet_ret != DBErrors::LOAD_OK)
    {
        fprintf(stderr, "Error creating %s", name.c_str());
        return NULL;
    }

    // From V0.16, all new wallets must be HD
    wallet_instance->SetMinVersion(FEATURE_HD_SPLIT);

    // generate a new HD seed
    CPubKey seed = wallet_instance->GenerateNewSeed();
    wallet_instance->SetHDSeed(seed);

    fprintf(stdout, "Topping up keypool...\n");
    wallet_instance->TopUpKeyPool();
    return wallet_instance;
}

static std::shared_ptr<CWallet> LoadWallet(const std::string name, const fs::path& path)
{
    if (!fs::exists(path))
    {
        fprintf(stderr, "Error: Wallet files does not exist\n");
        return NULL;
    }

    std::shared_ptr<CWallet> wallet_instance(new CWallet(name, WalletDatabase::Create(path)), ReleaseWallet);
    bool first_run;
    DBErrors load_wallet_ret = wallet_instance->LoadWallet(first_run);
    if (load_wallet_ret != DBErrors::LOAD_OK)
    {
        wallet_instance = NULL;
        if (load_wallet_ret == DBErrors::CORRUPT)
        {
            fprintf(stderr, "Error loading %s: Wallet corrupted", name.c_str());
            return NULL;
        }
        else if (load_wallet_ret == DBErrors::NONCRITICAL_ERROR)
        {
            fprintf(stderr, "Error reading %s! All keys read correctly, but transaction data"
                    " or address book entries might be missing or incorrect.",
                    name.c_str());
        }
        else if (load_wallet_ret == DBErrors::TOO_NEW)
        {
            fprintf(stderr, "Error loading %s: Wallet requires newer version of %s",
                    name.c_str(), PACKAGE_NAME);
            return NULL;
        }
        else if (load_wallet_ret == DBErrors::NEED_REWRITE)
        {
            fprintf(stderr, "Wallet needed to be rewritten: restart %s to complete", PACKAGE_NAME);
            return NULL;
        }
        else
        {
            fprintf(stderr, "Error loading %s", name.c_str());
            return NULL;
        }
    }

    return wallet_instance;
}

static void WalletShowInfo(std::shared_ptr<CWallet> wallet_instance)
{
    // lock required because of some AssertLockHeld()
    LOCK(wallet_instance->cs_wallet);

    fprintf(stdout, "Wallet info\n===========\n");
    fprintf(stdout, "Encrypted: %s\n",      wallet_instance->IsCrypted() ? "yes" : "no");
    fprintf(stdout, "HD (hd seed available): %s\n",             wallet_instance->GetHDChain().seed_id.IsNull() ? "no" : "yes");
    fprintf(stdout, "Keypool Size: %lu\n",  (unsigned long)wallet_instance->GetKeyPoolSize());
    fprintf(stdout, "Transactions: %lu\n",  (unsigned long)wallet_instance->mapWallet.size());
    fprintf(stdout, "Address Book: %lu\n",  (unsigned long)wallet_instance->mapAddressBook.size());
}

bool executeWalletToolFunc(const std::string& method, const std::string& name)
{
    fs::path path = fs::absolute(name, GetWalletDir());

    if (method == "create")
    {
        std::shared_ptr<CWallet> wallet_instance = CreateWallet(name, path);
        if (wallet_instance)
            WalletShowInfo(wallet_instance);
    }
    else if (method == "info")
    {
        std::shared_ptr<CWallet> wallet_instance = LoadWallet(name, path);
        if (!wallet_instance)
            return false;
        WalletShowInfo(wallet_instance);
    }
    else if (method == "salvage")
    {

        // Recover readable keypairs:
        std::string error;
        if (!WalletBatch::VerifyEnvironment(path, error)) {
            fprintf(stderr, "WalletBatch::VerifyEnvironment Error: %s\n", error.c_str());
            return false;
        }

        CWallet dummyWallet("dummy", WalletDatabase::CreateDummy());
        std::string backup_filename;
        if (!WalletBatch::Recover(path, (void *)&dummyWallet, WalletBatch::RecoverKeysOnlyFilter, backup_filename)) {
            fprintf(stderr, "Salvage failed\n");
            return false;
        }
        //TODO, set wallets best block to genesis to enforce a rescan
        fprintf(stdout, "Salvage successful. Please rescan your wallet.");
    }
    else if (method == "zaptxs")
    {
        // needed to restore wallet transaction meta data after -zapwallettxes
        std::vector<CWalletTx> vWtx;

        std::unique_ptr<CWallet> tempWallet = MakeUnique<CWallet>(name, WalletDatabase::Create(path));
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DBErrors::LOAD_OK) {
            fprintf(stderr, "Error loading %s: Wallet corrupted", name.c_str());
            return false;
        }
        fprintf(stdout, "Zaptxs successful executed. Please rescan your wallet.");
    }
    else {
        fprintf(stderr, "Unknown command\n");
    }

    return true;
}
}
