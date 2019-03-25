#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test compact blocks (BIP 152).

Version 1 compact blocks are pre-segwit (txids)
Version 2 compact blocks are post-segwit (wtxids)
"""
import random

from test_framework.blocktools import create_block, create_coinbase, add_witness_commitment
from test_framework.messages import BlockTransactions, BlockTransactionsRequest, calculate_shortid, CBlock, CBlockHeader, CInv, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, FromHex, HeaderAndShortIDs, msg_blocktxn, msg_cmpctblock, msg_getblocktxn, msg_getdata, msg_getheaders, msg_headers, msg_inv, msg_sendcmpct, msg_sendheaders, msg_tx, msg_witness_block, msg_witness_tx, msg_witness_blocktxn, MSG_WITNESS_FLAG, NODE_NETWORK, P2PHeaderAndShortIDs, PrefilledTransaction, ser_uint256, ToHex
from test_framework.mininode import mininode_lock, P2PInterface
from test_framework.script import CScript, OP_TRUE, OP_DROP
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_bip9_status, wait_until

# TestP2PConn: A peer we use to send messages to bitcoind, and store responses.
class TestP2PConn(P2PInterface):
    def __init__(self):
        super().__init__()
        self.last_sendcmpct = []
        self.block_announced = False
        # Store the hashes of blocks we've seen announced.
        # This is for synchronizing the p2p message traffic,
        # so we can eg wait until a particular block is announced.
        self.announced_blockhashes = set()

    def on_sendcmpct(self, message):
        self.last_sendcmpct.append(message)

    def on_cmpctblock(self, message):
        self.block_announced = True
        self.last_message["cmpctblock"].header_and_shortids.header.calc_sha256()
        self.announced_blockhashes.add(self.last_message["cmpctblock"].header_and_shortids.header.sha256)

    def on_headers(self, message):
        self.block_announced = True
        for x in self.last_message["headers"].headers:
            x.calc_sha256()
            self.announced_blockhashes.add(x.sha256)

    def on_inv(self, message):
        for x in self.last_message["inv"].inv:
            if x.type == 2:
                self.block_announced = True
                self.announced_blockhashes.add(x.hash)

    # Requires caller to hold mininode_lock
    def received_block_announcement(self):
        return self.block_announced

    def clear_block_announcement(self):
        with mininode_lock:
            self.block_announced = False
            self.last_message.pop("inv", None)
            self.last_message.pop("headers", None)
            self.last_message.pop("cmpctblock", None)

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.send_message(msg)

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_message(headers_message)

    def request_headers_and_sync(self, locator, hashstop=0):
        self.clear_block_announcement()
        self.get_headers(locator, hashstop)
        wait_until(self.received_block_announcement, timeout=30, lock=mininode_lock)
        self.clear_block_announcement()

    def wait_for_block_announcement(self, block_hash, timeout=30):
        def received_hash():
            return (block_hash in self.announced_blockhashes)
        wait_until(received_hash, timeout=timeout, lock=mininode_lock)

    def send_await_disconnect(self, message, timeout=30):
        """Sends a message to the node and wait for disconnect.

        This is used when we want to send a message into the node that we expect
        will get us disconnected, eg an invalid block."""
        self.send_message(message)
        wait_until(lambda: not self.is_connected, timeout=timeout, lock=mininode_lock)

class CompactBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.utxos = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def build_block_on_tip(self, node):
        """Builds a witness block on the tip."""
        height = node.getblockcount()
        tip = node.getbestblockhash()
        mtp = node.getblockheader(tip)['mediantime']
        block = create_block(int(tip, 16), create_coinbase(height + 1), mtp + 1)
        block.nVersion = 4
        add_witness_commitment(block)
        block.solve()
        return block

    def build_block_with_transactions(self, node, utxo, num_transactions):
        """Builds a witness block with num_transactions on the tip.

        The transactions are built as a chain based on utxo."""
        block = self.build_block_on_tip(node)

        for i in range(num_transactions):
            tx = CTransaction()
            tx.vin.append(CTxIn(COutPoint(utxo[0], utxo[1]), b''))
            tx.vout.append(CTxOut(utxo[2] - 1000, CScript([OP_TRUE, OP_DROP] * 15 + [OP_TRUE])))
            tx.rehash()
            utxo = [tx.sha256, 0, tx.vout[0].nValue]
            block.vtx.append(tx)

        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()
        return block

    def check_announcement_of_new_block(self, peer, predicate):
        """Generate a block on the node and check that it is announced to peer."""
        peer.clear_block_announcement()
        block_hash = int(self.nodes[0].generate(1)[0], 16)
        peer.wait_for_block_announcement(block_hash, timeout=30)
        assert peer.block_announced

        with mininode_lock:
            assert predicate(peer), (
                "block_hash={!r}, cmpctblock={!r}, inv={!r}".format(
                    block_hash, peer.last_message.get("cmpctblock", None), peer.last_message.get("inv", None)))

    def request_cb_announcements(self, peer):
        """Send a getheaders and a sendcmpct to the node."""
        tip = self.nodes[0].getbestblockhash()
        peer.get_headers(locator=[int(tip, 16)], hashstop=0)

        msg = msg_sendcmpct()
        msg.version = peer.version
        msg.announce = True
        peer.send_and_ping(msg)

    def run_test(self):
        # Setup the p2p connections
        self.segwit_peer_1 = self.nodes[0].add_p2p_connection(TestP2PConn())
        self.segwit_peer_1.version = 2
        self.segwit_peer_2 = self.nodes[0].add_p2p_connection(TestP2PConn())
        self.segwit_peer_2.version = 2
        self.legacy_peer = self.nodes[0].add_p2p_connection(TestP2PConn(), services=NODE_NETWORK)
        self.legacy_peer.version = 1

        # Construct UTXOs for use in later tests.
        self.make_utxos(self.segwit_peer_1)

        assert_equal(get_bip9_status(self.nodes[0], "segwit")["status"], 'active')

        self.log.info("Testing SENDCMPCT p2p message... ")
        self.test_sendcmpct(self.segwit_peer_1)
        self.test_sendcmpct(self.segwit_peer_2)
        self.test_sendcmpct_legacy(self.legacy_peer)

        self.log.info("Testing compactblock construction...")
        self.test_compactblock_construction(self.legacy_peer)
        self.test_compactblock_construction(self.segwit_peer_1)

        self.log.info("Testing compactblock requests...")
        self.test_compactblock_requests(self.segwit_peer_1)

        self.log.info("Testing getblocktxn requests...")
        self.test_getblocktxn_requests(self.segwit_peer_1)

        self.log.info("Testing getblocktxn handler...")
        self.test_getblocktxn_handler(self.segwit_peer_1)
        self.test_getblocktxn_handler(self.legacy_peer)

        self.log.info("Testing compactblock requests/announcements not at chain tip...")
        self.test_compactblocks_not_at_tip(self.segwit_peer_1)
        self.test_compactblocks_not_at_tip(self.legacy_peer)

        self.log.info("Testing handling of incorrect blocktxn responses...")
        self.test_incorrect_blocktxn_response(self.segwit_peer_1)

        self.log.info("Testing reconstructing compact blocks from all peers...")
        self.test_compactblock_reconstruction_multiple_peers(self.segwit_peer_1, self.segwit_peer_2)

        self.log.info("Testing end-to-end block relay...")
        self.test_end_to_end_block_relay([self.segwit_peer_1, self.legacy_peer])

        self.log.info("Testing handling of invalid compact blocks...")
        self.test_invalid_tx_in_compactblock(self.segwit_peer_1)
        self.test_invalid_tx_in_compactblock(self.legacy_peer)

        self.log.info("Testing invalid index in cmpctblock message...")
        self.test_invalid_cmpctblock_message(self.segwit_peer_1)

    def make_utxos(self, peer):
        """ Create 10 anyone-can-spend UTXOs for testing and send balance to bech32 output."""
        block = self.build_block_on_tip(self.nodes[0])
        peer.send_and_ping(msg_witness_block(block))
        assert int(self.nodes[0].getbestblockhash(), 16) == block.sha256
        address = self.nodes[0].getnewaddress(address_type="bech32")
        self.nodes[0].generatetoaddress(100, address)

        total_value = block.vtx[0].vout[0].nValue
        out_value = total_value // 10
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(block.vtx[0].sha256, 0), b''))
        for i in range(10):
            tx.vout.append(CTxOut(out_value, CScript([OP_TRUE])))
        tx.rehash()

        block2 = self.build_block_on_tip(self.nodes[0])
        block2.vtx.append(tx)
        block2.hashMerkleRoot = block2.calc_merkle_root()
        add_witness_commitment(block2)
        block2.solve()
        peer.send_and_ping(msg_witness_block(block2))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block2.sha256)
        self.utxos.extend([[tx.sha256, i, out_value] for i in range(10)])

    def test_sendcmpct(self, peer, legacy_peer=None):
        """Test sendcmpct between peers preferring the same version

        - No compact block announcements unless sendcmpct is sent.
        - If sendcmpct is sent with version > preferred_version, the message is ignored.
        - If sendcmpct is sent with boolean 0, then block announcements are not
          made with compact blocks.
        - If sendcmpct is then sent with boolean 1, then new block announcements
          are made with compact blocks."""

        # Make sure we get a SENDCMPCT message from our peer
        def received_sendcmpct():
            return (len(peer.last_sendcmpct) > 0)
        wait_until(received_sendcmpct, timeout=30, lock=mininode_lock)
        with mininode_lock:
            # Check that we receive version 2 first.
            assert_equal(peer.last_sendcmpct[0].version, 2)
            # And that we receive version 1.
            assert_equal(peer.last_sendcmpct[-1].version, 1)
            peer.last_sendcmpct = []

        tip = int(self.nodes[0].getbestblockhash(), 16)

        # We shouldn't get any block announcements via cmpctblock yet.
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" not in p.last_message)

        # Try one more time, this time after requesting headers.
        peer.request_headers_and_sync(locator=[tip])
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" not in p.last_message and "inv" in p.last_message)

        # Test a few ways of using sendcmpct that should NOT
        # result in compact block announcements.
        # Before each test, sync the headers chain.
        peer.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with too-high version
        sendcmpct = msg_sendcmpct()
        sendcmpct.version = 3
        sendcmpct.announce = True
        peer.send_and_ping(sendcmpct)
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" not in p.last_message)

        # Headers sync before next test.
        peer.request_headers_and_sync(locator=[tip])

        # Now try a SENDCMPCT message with valid version, but announce=False
        sendcmpct.version = 2
        sendcmpct.announce = False
        peer.send_and_ping(sendcmpct)
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" not in p.last_message)

        # Headers sync before next test.
        peer.request_headers_and_sync(locator=[tip])

        # Finally, try a SENDCMPCT message with announce=True
        sendcmpct.version = 2
        sendcmpct.announce = True
        peer.send_and_ping(sendcmpct)
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" in p.last_message)

        # Try one more time (no headers sync should be needed!)
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" in p.last_message)

        # Try one more time, after turning on sendheaders
        peer.send_and_ping(msg_sendheaders())
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" in p.last_message)

        # Try one more time, after sending version 1, announce=false message.
        sendcmpct.version = 1
        sendcmpct.announce = False
        peer.send_and_ping(sendcmpct)
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" in p.last_message)

        # Now turn off announcements
        sendcmpct.version = 2
        sendcmpct.announce = False
        peer.send_and_ping(sendcmpct)
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" not in p.last_message and "headers" in p.last_message)

    def test_sendcmpct_legacy(self, peer):
        """Verify that a peer using an older protocol version can receive announcements from this node."""
        sendcmpct = msg_sendcmpct()
        sendcmpct.version = 1
        sendcmpct.announce = True
        peer.send_and_ping(sendcmpct)
        # Header sync
        tip = int(self.nodes[0].getbestblockhash(), 16)
        peer.request_headers_and_sync(locator=[tip])
        self.check_announcement_of_new_block(peer, lambda p: "cmpctblock" in p.last_message)

    def test_compactblock_construction(self, peer):
        """Compare the generated shortids to what we expect based on BIP 152, given bitcoind's choice of nonce."""

        # Generate a bunch of transactions.
        self.nodes[0].generate(101)
        num_transactions = 25
        address = self.nodes[0].getnewaddress()

        segwit_tx_generated = False
        for i in range(num_transactions):
            txid = self.nodes[0].sendtoaddress(address, 0.1)
            hex_tx = self.nodes[0].gettransaction(txid)["hex"]
            tx = FromHex(CTransaction(), hex_tx)
            if not tx.wit.is_null():
                segwit_tx_generated = True

        # check that our test is not broken
        assert segwit_tx_generated

        # Wait until we've seen the block announcement for the resulting tip
        tip = int(self.nodes[0].getbestblockhash(), 16)
        peer.wait_for_block_announcement(tip)

        # Make sure we will receive a fast-announce compact block
        self.request_cb_announcements(peer)

        # Now mine a block, and look at the resulting compact block.
        peer.clear_block_announcement()
        block_hash = int(self.nodes[0].generate(1)[0], 16)

        # Store the raw block in our internal format.
        block = FromHex(CBlock(), self.nodes[0].getblock("%064x" % block_hash, False))
        for tx in block.vtx:
            tx.calc_sha256()
        block.rehash()

        # Wait until the block was announced (via compact blocks)
        wait_until(peer.received_block_announcement, timeout=30, lock=mininode_lock)

        # Now fetch and check the compact block
        header_and_shortids = None
        with mininode_lock:
            assert "cmpctblock" in peer.last_message
            # Convert the on-the-wire representation to absolute indexes
            header_and_shortids = HeaderAndShortIDs(peer.last_message["cmpctblock"].header_and_shortids)
        self.check_compactblock_construction_from_block(peer.version, header_and_shortids, block_hash, block)

        # Now fetch the compact block using a normal non-announce getdata
        with mininode_lock:
            peer.clear_block_announcement()
            inv = CInv(4, block_hash)  # 4 == "CompactBlock"
            peer.send_message(msg_getdata([inv]))

        wait_until(peer.received_block_announcement, timeout=30, lock=mininode_lock)

        # Now fetch and check the compact block
        header_and_shortids = None
        with mininode_lock:
            assert "cmpctblock" in peer.last_message
            # Convert the on-the-wire representation to absolute indexes
            header_and_shortids = HeaderAndShortIDs(peer.last_message["cmpctblock"].header_and_shortids)
        self.check_compactblock_construction_from_block(peer.version, header_and_shortids, block_hash, block)

    def check_compactblock_construction_from_block(self, version, header_and_shortids, block_hash, block):
        """Check that the compact block sent to the peer is correct."""
        header_and_shortids.header.calc_sha256()
        assert_equal(header_and_shortids.header.sha256, block_hash)

        # Make sure the prefilled_txn appears to have included the coinbase
        assert len(header_and_shortids.prefilled_txn) >= 1
        assert_equal(header_and_shortids.prefilled_txn[0].index, 0)

        # Check that all prefilled_txn entries match what's in the block.
        for entry in header_and_shortids.prefilled_txn:
            entry.tx.calc_sha256()
            # This checks the non-witness parts of the tx agree
            assert_equal(entry.tx.sha256, block.vtx[entry.index].sha256)

            # And this checks the witness
            wtxid = entry.tx.calc_sha256(True)
            if version == 2:
                assert_equal(wtxid, block.vtx[entry.index].calc_sha256(True))
            else:
                # Shouldn't have received a witness
                assert entry.tx.wit.is_null()

        # Check that the cmpctblock message announced all the transactions.
        assert_equal(len(header_and_shortids.prefilled_txn) + len(header_and_shortids.shortids), len(block.vtx))

        # And now check that all the shortids are as expected as well.
        # Determine the siphash keys to use.
        [k0, k1] = header_and_shortids.get_siphash_keys()

        index = 0
        while index < len(block.vtx):
            if (len(header_and_shortids.prefilled_txn) > 0 and
                    header_and_shortids.prefilled_txn[0].index == index):
                # Already checked prefilled transactions above
                header_and_shortids.prefilled_txn.pop(0)
            else:
                tx_hash = block.vtx[index].sha256
                if version == 2:
                    tx_hash = block.vtx[index].calc_sha256(True)
                shortid = calculate_shortid(k0, k1, tx_hash)
                assert_equal(shortid, header_and_shortids.shortids[0])
                header_and_shortids.shortids.pop(0)
            index += 1

    def test_compactblock_requests(self, peer):
        """Test compactblock requests:

        - bitcoind requests compact blocks when we announce new blocks via header or inv
        - responding to getblocktxn causes the block to be successfully reconstructed."""

        # Try announcing a block with an inv or header, expect a compactblock
        # request
        for announce in ["inv", "header"]:
            block = self.build_block_on_tip(self.nodes[0])
            with mininode_lock:
                peer.last_message.pop("getdata", None)

            if announce == "inv":
                peer.send_message(msg_inv([CInv(2, block.sha256)]))
                wait_until(lambda: "getheaders" in peer.last_message, timeout=30, lock=mininode_lock)
                peer.send_header_for_blocks([block])
            else:
                peer.send_header_for_blocks([block])
            wait_until(lambda: "getdata" in peer.last_message, timeout=30, lock=mininode_lock)
            assert_equal(len(peer.last_message["getdata"].inv), 1)
            assert_equal(peer.last_message["getdata"].inv[0].type, 4)
            assert_equal(peer.last_message["getdata"].inv[0].hash, block.sha256)

            # Send back a compactblock message that omits the coinbase
            comp_block = HeaderAndShortIDs()
            comp_block.header = CBlockHeader(block)
            comp_block.nonce = 0
            [k0, k1] = comp_block.get_siphash_keys()
            coinbase_hash = block.vtx[0].sha256
            coinbase_hash = block.vtx[0].calc_sha256(True)
            comp_block.shortids = [calculate_shortid(k0, k1, coinbase_hash)]
            peer.send_and_ping(msg_cmpctblock(comp_block.to_p2p()))
            assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)
            # Expect a getblocktxn message.
            with mininode_lock:
                assert "getblocktxn" in peer.last_message
                absolute_indexes = peer.last_message["getblocktxn"].block_txn_request.to_absolute()
            assert_equal(absolute_indexes, [0])  # should be a coinbase request

            # Send the coinbase, and verify that the tip advances.
            msg = msg_witness_blocktxn()
            msg.block_transactions.blockhash = block.sha256
            msg.block_transactions.transactions = [block.vtx[0]]
            peer.send_and_ping(msg)
            assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)

    def test_getblocktxn_requests(self, peer):
        """Test getblocktxs requests

        The peer should only receive getblocktxn requests for transactions that the
        node needs. Responding to them causes the block to be reconstructed."""

        def test_getblocktxn_response(compact_block, peer, expected_result):
            msg = msg_cmpctblock(compact_block.to_p2p())
            peer.send_and_ping(msg)
            with mininode_lock:
                assert "getblocktxn" in peer.last_message
                absolute_indexes = peer.last_message["getblocktxn"].block_txn_request.to_absolute()
            assert_equal(absolute_indexes, expected_result)

        def test_tip_after_message(node, peer, msg, tip):
            peer.send_and_ping(msg)
            assert_equal(int(node.getbestblockhash(), 16), tip)

        # First try announcing compactblocks that won't reconstruct, and verify
        # that we receive getblocktxn messages back.
        utxo = self.utxos.pop(0)

        block = self.build_block_with_transactions(self.nodes[0], utxo, 5)
        self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])
        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block, use_witness=True)

        test_getblocktxn_response(comp_block, peer, [1, 2, 3, 4, 5])

        msg_bt = msg_witness_blocktxn()  # serialize with witnesses
        msg_bt.block_transactions = BlockTransactions(block.sha256, block.vtx[1:])
        test_tip_after_message(self.nodes[0], peer, msg_bt, block.sha256)

        utxo = self.utxos.pop(0)
        block = self.build_block_with_transactions(self.nodes[0], utxo, 5)
        self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])

        # Now try interspersing the prefilled transactions
        comp_block.initialize_from_block(block, prefill_list=[0, 1, 5], use_witness=True)
        test_getblocktxn_response(comp_block, peer, [2, 3, 4])
        msg_bt.block_transactions = BlockTransactions(block.sha256, block.vtx[2:5])
        test_tip_after_message(self.nodes[0], peer, msg_bt, block.sha256)

        # Now try giving one transaction ahead of time.
        utxo = self.utxos.pop(0)
        block = self.build_block_with_transactions(self.nodes[0], utxo, 5)
        self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])
        peer.send_and_ping(msg_tx(block.vtx[1]))
        assert block.vtx[1].hash in self.nodes[0].getrawmempool()

        # Prefill 4 out of the 6 transactions, and verify that only the one
        # that was not in the mempool is requested.
        comp_block.initialize_from_block(block, prefill_list=[0, 2, 3, 4], use_witness=True)
        test_getblocktxn_response(comp_block, peer, [5])

        msg_bt.block_transactions = BlockTransactions(block.sha256, [block.vtx[5]])
        test_tip_after_message(self.nodes[0], peer, msg_bt, block.sha256)

        # Now provide all transactions to the node before the block is
        # announced and verify reconstruction happens immediately.
        utxo = self.utxos.pop(0)
        block = self.build_block_with_transactions(self.nodes[0], utxo, 10)
        self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])
        for tx in block.vtx[1:]:
            peer.send_message(msg_tx(tx))
        peer.sync_with_ping()
        # Make sure all transactions were accepted.
        mempool = self.nodes[0].getrawmempool()
        for tx in block.vtx[1:]:
            assert tx.hash in mempool

        # Clear out last request.
        with mininode_lock:
            peer.last_message.pop("getblocktxn", None)

        # Send compact block
        comp_block.initialize_from_block(block, prefill_list=[0], use_witness=True)
        test_tip_after_message(self.nodes[0], peer, msg_cmpctblock(comp_block.to_p2p()), block.sha256)
        with mininode_lock:
            # Shouldn't have gotten a request for any transaction
            assert "getblocktxn" not in peer.last_message

    def test_getblocktxn_handler(self, peer):
        """Test that bitcoind will not send blocktxn responses for old blocks.

        10 blocks is the max depth for requesting blocktxns."""
        MAX_GETBLOCKTXN_DEPTH = 10
        chain_height = self.nodes[0].getblockcount()
        current_height = chain_height
        while (current_height >= chain_height - MAX_GETBLOCKTXN_DEPTH):
            block_hash = self.nodes[0].getblockhash(current_height)
            block = FromHex(CBlock(), self.nodes[0].getblock(block_hash, False))

            msg = msg_getblocktxn()
            msg.block_txn_request = BlockTransactionsRequest(int(block_hash, 16), [])
            num_to_request = random.randint(1, len(block.vtx))
            msg.block_txn_request.from_absolute(sorted(random.sample(range(len(block.vtx)), num_to_request)))
            peer.send_message(msg)
            wait_until(lambda: "blocktxn" in peer.last_message, timeout=10, lock=mininode_lock)

            [tx.calc_sha256() for tx in block.vtx]
            with mininode_lock:
                assert_equal(peer.last_message["blocktxn"].block_transactions.blockhash, int(block_hash, 16))
                all_indices = msg.block_txn_request.to_absolute()
                for index in all_indices:
                    tx = peer.last_message["blocktxn"].block_transactions.transactions.pop(0)
                    tx.calc_sha256()
                    assert_equal(tx.sha256, block.vtx[index].sha256)
                    if peer.version == 1:
                        # Witnesses should have been stripped
                        assert tx.wit.is_null()
                    else:
                        # Check that the witness matches
                        assert_equal(tx.calc_sha256(True), block.vtx[index].calc_sha256(True))
                peer.last_message.pop("blocktxn", None)
            current_height -= 1

        # Next request should send a full block response, as we're past the
        # allowed depth for a blocktxn response.
        block_hash = self.nodes[0].getblockhash(current_height)
        msg.block_txn_request = BlockTransactionsRequest(int(block_hash, 16), [0])
        with mininode_lock:
            peer.last_message.pop("block", None)
            peer.last_message.pop("blocktxn", None)
        peer.send_and_ping(msg)
        with mininode_lock:
            peer.last_message["block"].block.calc_sha256()
            assert_equal(peer.last_message["block"].block.sha256, int(block_hash, 16))
            assert "blocktxn" not in peer.last_message

    def test_compactblocks_not_at_tip(self, peer):
        """Test that bitcoind will not send compact blocks for old blocks.

        5 blocks is the max depth for requesting compact blocks."""
        MAX_CMPCTBLOCK_DEPTH = 5
        new_blocks = []
        for i in range(MAX_CMPCTBLOCK_DEPTH + 1):
            peer.clear_block_announcement()
            new_blocks.append(self.nodes[0].generate(1)[0])
            wait_until(peer.received_block_announcement, timeout=30, lock=mininode_lock)

        peer.clear_block_announcement()
        peer.send_message(msg_getdata([CInv(4, int(new_blocks[0], 16))]))
        wait_until(lambda: "cmpctblock" in peer.last_message, timeout=30, lock=mininode_lock)

        peer.clear_block_announcement()
        self.nodes[0].generate(1)
        wait_until(peer.received_block_announcement, timeout=30, lock=mininode_lock)
        peer.clear_block_announcement()
        with mininode_lock:
            peer.last_message.pop("block", None)
        peer.send_message(msg_getdata([CInv(4, int(new_blocks[0], 16))]))
        wait_until(lambda: "block" in peer.last_message, timeout=30, lock=mininode_lock)
        with mininode_lock:
            peer.last_message["block"].block.calc_sha256()
            assert_equal(peer.last_message["block"].block.sha256, int(new_blocks[0], 16))

        # Generate an old compactblock, and verify that it's not accepted.
        cur_height = self.nodes[0].getblockcount()
        hashPrevBlock = int(self.nodes[0].getblockhash(cur_height - 5), 16)
        block = self.build_block_on_tip(self.nodes[0])
        block.hashPrevBlock = hashPrevBlock
        block.solve()

        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block)
        peer.send_and_ping(msg_cmpctblock(comp_block.to_p2p()))

        tips = self.nodes[0].getchaintips()
        found = False
        for x in tips:
            if x["hash"] == block.hash:
                assert_equal(x["status"], "headers-only")
                found = True
                break
        assert found

        # Requesting this block via getblocktxn should silently fail
        # (to avoid fingerprinting attacks).
        msg = msg_getblocktxn()
        msg.block_txn_request = BlockTransactionsRequest(block.sha256, [0])
        with mininode_lock:
            peer.last_message.pop("blocktxn", None)
        peer.send_and_ping(msg)
        with mininode_lock:
            assert "blocktxn" not in peer.last_message

    def test_incorrect_blocktxn_response(self, peer):
        """Test that blocks aren't permanently failed if an incorrect response to a getblocktxn is received."""
        utxo = self.utxos.pop(0)

        block = self.build_block_with_transactions(self.nodes[0], utxo, 10)
        self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])
        # Relay the first 5 transactions from the block in advance
        for tx in block.vtx[1:6]:
            peer.send_message(msg_tx(tx))
        peer.sync_with_ping()
        # Make sure all transactions were accepted.
        mempool = self.nodes[0].getrawmempool()
        for tx in block.vtx[1:6]:
            assert tx.hash in mempool

        # Send compact block
        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block, prefill_list=[0], use_witness=True)
        peer.send_and_ping(msg_cmpctblock(comp_block.to_p2p()))
        absolute_indexes = []
        with mininode_lock:
            assert "getblocktxn" in peer.last_message
            absolute_indexes = peer.last_message["getblocktxn"].block_txn_request.to_absolute()
        assert_equal(absolute_indexes, [6, 7, 8, 9, 10])

        # Now give an incorrect response.
        # Note that it's possible for bitcoind to be smart enough to know we're
        # lying, since it could check to see if the shortid matches what we're
        # sending, and eg disconnect us for misbehavior.  If that behavior
        # change was made, we could just modify this test by having a
        # different peer provide the block further down, so that we're still
        # verifying that the block isn't marked bad permanently. This is good
        # enough for now.
        msg = msg_witness_blocktxn()
        msg.block_transactions = BlockTransactions(block.sha256, [block.vtx[5]] + block.vtx[7:])
        peer.send_and_ping(msg)

        # Tip should not have updated
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

        # We should receive a getdata request
        wait_until(lambda: "getdata" in peer.last_message, timeout=10, lock=mininode_lock)
        assert_equal(len(peer.last_message["getdata"].inv), 1)
        assert peer.last_message["getdata"].inv[0].type == 2 or peer.last_message["getdata"].inv[0].type == 2 | MSG_WITNESS_FLAG
        assert_equal(peer.last_message["getdata"].inv[0].hash, block.sha256)

        # Deliver the block
        peer.send_and_ping(msg_witness_block(block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)

    def test_compactblock_reconstruction_multiple_peers(self, stalling_peer, delivery_peer):
        """Test that a compact block can be reconstructed from multiple peers."""
        assert len(self.utxos)

        def announce_cmpct_block(node, peer):
            utxo = self.utxos.pop(0)
            block = self.build_block_with_transactions(node, utxo, 5)

            cmpct_block = HeaderAndShortIDs()
            cmpct_block.initialize_from_block(block, use_witness=True)
            msg = msg_cmpctblock(cmpct_block.to_p2p())
            peer.send_and_ping(msg)
            with mininode_lock:
                assert "getblocktxn" in peer.last_message
            return block, cmpct_block

        block, cmpct_block = announce_cmpct_block(self.nodes[0], stalling_peer)

        for tx in block.vtx[1:]:
            delivery_peer.send_message(msg_witness_tx(tx))
        delivery_peer.sync_with_ping()
        mempool = self.nodes[0].getrawmempool()
        for tx in block.vtx[1:]:
            assert tx.hash in mempool

        delivery_peer.send_and_ping(msg_cmpctblock(cmpct_block.to_p2p()))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)

        # self.utxos.append([block.vtx[-1].sha256, 0, block.vtx[-1].vout[0].nValue])

        # Now test that delivering an invalid compact block won't break relay

        block, cmpct_block = announce_cmpct_block(self.nodes[0], stalling_peer)
        for tx in block.vtx[1:]:
            delivery_peer.send_message(msg_witness_tx(tx))
        delivery_peer.sync_with_ping()

        cmpct_block.prefilled_txn[0].tx.wit.vtxinwit = [CTxInWitness()]
        cmpct_block.prefilled_txn[0].tx.wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(1)]

        cmpct_block.use_witness = True
        delivery_peer.send_and_ping(msg_cmpctblock(cmpct_block.to_p2p()))
        assert int(self.nodes[0].getbestblockhash(), 16) != block.sha256

        msg = msg_blocktxn()
        msg.block_transactions.blockhash = block.sha256
        msg.block_transactions.transactions = block.vtx[1:]
        stalling_peer.send_and_ping(msg)
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)

    def test_end_to_end_block_relay(self, peers):
        """Test that if we submitblock to the node, we'll get a compact block announcement to all peers."""
        for peer in peers:
            self.request_cb_announcements(peer)
        utxo = self.utxos.pop(0)

        block = self.build_block_with_transactions(self.nodes[0], utxo, 10)

        [l.clear_block_announcement() for l in peers]

        # ToHex() won't serialize with witness, but this block has no witnesses
        # anyway. TODO: repeat this test with witness tx's to a segwit node.
        self.nodes[0].submitblock(ToHex(block))

        for l in peers:
            wait_until(lambda: l.received_block_announcement(), timeout=30, lock=mininode_lock)
        with mininode_lock:
            for l in peers:
                assert "cmpctblock" in l.last_message
                l.last_message["cmpctblock"].header_and_shortids.header.calc_sha256()
                assert_equal(l.last_message["cmpctblock"].header_and_shortids.header.sha256, block.sha256)

    def test_invalid_tx_in_compactblock(self, peer, use_segwit=True):
        """Test that we don't get disconnected if we relay a compact block with valid header and invalid transactions."""
        assert len(self.utxos)
        utxo = self.utxos[0]

        block = self.build_block_with_transactions(self.nodes[0], utxo, 5)
        del block.vtx[3]
        block.hashMerkleRoot = block.calc_merkle_root()
        if use_segwit:
            # If we're testing with segwit, also drop the coinbase witness,
            # but include the witness commitment.
            add_witness_commitment(block)
            block.vtx[0].wit.vtxinwit = []
        block.solve()

        # Now send the compact block with all transactions prefilled, and
        # verify that we don't get disconnected.
        comp_block = HeaderAndShortIDs()
        comp_block.initialize_from_block(block, prefill_list=[0, 1, 2, 3, 4], use_witness=use_segwit)
        msg = msg_cmpctblock(comp_block.to_p2p())
        peer.send_and_ping(msg)

        # Check that the tip didn't advance
        assert int(self.nodes[0].getbestblockhash(), 16) is not block.sha256
        peer.sync_with_ping()

    def test_invalid_cmpctblock_message(self, peer):
        """Test that the node disconnects a peer that sends an invalid compact block."""
        self.nodes[0].generate(101)
        block = self.build_block_on_tip(self.nodes[0])

        cmpct_block = P2PHeaderAndShortIDs()
        cmpct_block.header = CBlockHeader(block)
        cmpct_block.prefilled_txn_length = 1
        # This index will be too high
        prefilled_txn = PrefilledTransaction(1, block.vtx[0])
        cmpct_block.prefilled_txn = [prefilled_txn]
        peer.send_await_disconnect(msg_cmpctblock(cmpct_block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.hashPrevBlock)

if __name__ == '__main__':
    CompactBlocksTest().main()
