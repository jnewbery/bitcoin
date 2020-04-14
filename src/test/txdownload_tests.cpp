// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/txdownload.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(txdownload_tests)

BOOST_AUTO_TEST_CASE(txdownload)
{
    TxDownloadState tx_download_state;

    uint256 tx1 = InsecureRand256();
    uint256 tx2 = InsecureRand256();
    uint256 tx3 = InsecureRand256();

    tx_download_state.AddAnnouncedTx(tx1, std::chrono::microseconds(1000) /*time to attempt request*/);
    tx_download_state.AddAnnouncedTx(tx2, std::chrono::microseconds(1500) /*time to attempt request*/);
    tx_download_state.AddAnnouncedTx(tx3, std::chrono::microseconds(2000) /*time to attempt request*/);

    int i{0};
    uint256 tx;
    while (tx_download_state.GetAnnouncedTxToRequest(std::chrono::microseconds(1500), tx)) ++i;

    BOOST_CHECK(2 == i);
}

BOOST_AUTO_TEST_SUITE_END()
