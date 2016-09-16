// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparams.h>
#include <chainparamsbase.h>
#include <consensus/consensus.h>
#include <logging.h>
#include <util.h>
#include <utilstrencodings.h>
#include <wallet/wallettools.h>

#include <stdio.h>


std::string HelpMessageCli()
{
    std::string usage;
    usage += HelpMessageGroup(_("Options:"));
    usage += HelpMessageOpt("-?", _("This help message"));
    usage += HelpMessageOpt("-file=<wallet-file>", strprintf(_("Specify wallet.dat file")));

    usage += HelpMessageGroup(_("Commands:"));
    usage += HelpMessageOpt("info", _("Get wallet info"));
    usage += HelpMessageOpt("create", _("Create new wallet file"));
    usage += HelpMessageOpt("salvage", _("Recover readable keypairs"));
    usage += HelpMessageOpt("zaptxs", _("Remove all transactions including metadata (will keep keys)"));

    return usage;
}

static bool WalletAppInit(int argc, char* argv[])
{
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        fprintf(stderr, "Error parsing command line arguments: %s\n", error.c_str());
        return EXIT_FAILURE;
    }
    if (argc<2 || gArgs.IsArgSet("-?") || gArgs.IsArgSet("-h") || gArgs.IsArgSet("-help") || gArgs.IsArgSet("-version")) {
        std::string usage = strprintf(_("%s wallet-tool version"), PACKAGE_NAME) + " " + FormatFullVersion() + "\n";
        if (!gArgs.IsArgSet("-version")) {
            usage += "\n" + _("Usage:") + "\n" +
            "  bitcoin-wallet-tool [options] <command>\n";
            usage += "\n" + HelpMessageCli();
        }

        fprintf(stdout, "%s", usage.c_str());
        return false;
    }

    // check for printtoconsole, allow -debug
    g_logger->m_print_to_console = gArgs.GetBoolArg("-printtoconsole", gArgs.GetBoolArg("-debug", false));

    // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    try {
        SelectParams(gArgs.GetChainName());
    } catch (const std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return true;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();
    RandomInit();
    try {
        if(!WalletAppInit(argc, argv))
        return EXIT_FAILURE;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "WalletAppInit()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(NULL, "WalletAppInit()");
        return EXIT_FAILURE;
    }

    while (argc > 1 && IsSwitchChar(argv[1][0])) {
        argc--;
        argv++;
    }
    std::vector<std::string> args = std::vector<std::string>(&argv[1], &argv[argc]);
    std::string method = args[0];

    std::string file = gArgs.GetArg("-file", "");

    ECCVerifyHandle globalVerifyHandle;
    ECC_Start();
    if (!WalletTool::executeWalletToolFunc(method, file))
        return EXIT_FAILURE;
    ECC_Stop();
    return true;
}
