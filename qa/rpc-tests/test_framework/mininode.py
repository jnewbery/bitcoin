#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin P2P network half-a-node.

This python code was modified from ArtForz' public domain  half-a-node, as
found in the mini-node branch of http://github.com/jgarzik/pynode.

NodeConn: an object which manages p2p connectivity to a bitcoin node
NodeConnCB: a base class that describes the interface for receiving
            callbacks with network messages from a NodeConn
CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives
msg_block, msg_tx, msg_headers, etc.:
    data structures that represent network messages
ser_*, deser_*: functions that handle serialization/deserialization
"""

import asyncore
from collections import defaultdict
from io import BytesIO
import logging
import socket
import struct
import sys
from threading import (RLock,
                       Thread)
import time

from .primitives import (BIP0031_VERSION,
                         CBlock,
                         CInv,
                         MY_VERSION,
                         NODE_NETWORK,
                         msg_addr,
                         msg_alert,
                         msg_block,
                         msg_blocktxn,
                         msg_cmpctblock,
                         msg_feefilter,
                         msg_getaddr,
                         msg_getblocks,
                         msg_getblocktxn,
                         msg_getdata,
                         msg_getheaders,
                         msg_headers,
                         msg_inv,
                         msg_mempool,
                         msg_ping_prebip31,
                         msg_ping,
                         msg_pong,
                         msg_reject,
                         msg_sendcmpct,
                         msg_sendheaders,
                         msg_tx,
                         msg_verack,
                         msg_version,
                         sha256)

# Keep our own socket map for asyncore, so that we can track disconnects
# ourselves (to workaround an issue with closing an asyncore socket when
# using select)
mininode_socket_map = dict()

# One lock for synchronizing all data access between the networking thread (see
# NetworkThread below) and the thread running the test logic.  For simplicity,
# NodeConn acquires this lock whenever delivering a message to to a NodeConnCB,
# and whenever adding anything to the send buffer (in send_message()).  This
# lock should be acquired in the thread running the test logic to synchronize
# access to any data shared with the NodeConnCB or NodeConn.
mininode_lock = RLock()

# Helper function
def wait_until(predicate, *, attempts=float('inf'), timeout=float('inf')):
    attempt = 0
    elapsed = 0

    while attempt < attempts and elapsed < timeout:
        with mininode_lock:
            if predicate():
                return True
        attempt += 1
        elapsed += 0.05
        time.sleep(0.05)

    return False

class NodeConnCB(object):
    """Callback and helper functions for P2P connection to a bitcoind node.

    Individual testcases should subclass this and override the on_* methods
    if they want to alter message handling behaviour.
    """

    def __init__(self):
        # Track whether we have a P2P connection open to the node
        self.connected = False
        self.connection = None

        # Track number of messages of each type received and the most recent
        # message of each type
        self.message_count = defaultdict(int)
        self.last_message = {}

        # A count of the number of ping messages we've sent to the node
        self.ping_counter = 1

        # deliver_sleep_time is helpful for debugging race conditions in p2p
        # tests; it causes message delivery to sleep for the specified time
        # before acquiring the global lock and delivering the next message.
        self.deliver_sleep_time = None

        # Remember the services our peer has advertised
        self.peer_services = None

    # Connection methods
    def add_connection(self, conn):
        self.connection = conn

    def on_open(self, conn):
        self.connected = True

    def on_close(self, conn):
        self.connected = False
        self.connection = None

    def wait_for_disconnect(self, timeout=60):
        test_function = lambda: not self.connected
        assert wait_until(test_function, timeout=timeout)

    # Message receiving functions

    def deliver(self, conn, message):
        """Receive message and dispatch message to appropriate callback.

        We keep a count of how many of each message type has been received
        and the most recent message of each type.

        Optionally waits for deliver_sleep_time before dispatching message.
        """

        deliver_sleep = self.get_deliver_sleep_time()
        if deliver_sleep is not None:
            time.sleep(deliver_sleep)
        with mininode_lock:
            try:
                command = message.command.decode('ascii')
                self.message_count[command] += 1
                self.last_message[command] = message
                getattr(self, 'on_' + command)(conn, message)
            except:
                print("ERROR delivering %s (%s)" % (repr(message),
                                                    sys.exc_info()[0]))

    def set_deliver_sleep_time(self, value):
        with mininode_lock:
            self.deliver_sleep_time = value

    def get_deliver_sleep_time(self):
        with mininode_lock:
            return self.deliver_sleep_time

    # Callback functions. Can be overridden by subclasses in individual test cases to provide
    # custom message handling behaviour.

    def on_version(self, conn, message):
        if message.nVersion >= 209:
            conn.send_message(msg_verack())
        conn.ver_send = min(MY_VERSION, message.nVersion)
        if message.nVersion < 209:
            conn.ver_recv = conn.ver_send
        conn.nServices = message.nServices

    def on_verack(self, conn, message):
        conn.ver_recv = conn.ver_send

    def on_inv(self, conn, message):
        want = msg_getdata()
        for i in message.inv:
            if i.type:
                want.inv.append(i)
        if want.inv:
            conn.send_message(want)

    def on_ping(self, conn, message):
        if conn.ver_send > BIP0031_VERSION:
            conn.send_message(msg_pong(message.nonce))

    def on_addr(self, conn, message): pass
    def on_alert(self, conn, message): pass
    def on_block(self, conn, message): pass
    def on_blocktxn(self, conn, message): pass
    def on_cmpctblock(self, conn, message): pass
    def on_feefilter(self, conn, message): pass
    def on_getaddr(self, conn, message): pass
    def on_getblocks(self, conn, message): pass
    def on_getblocktxn(self, conn, message): pass
    def on_getdata(self, conn, message): pass
    def on_getheaders(self, conn, message): pass
    def on_headers(self, conn, message): pass
    def on_mempool(self, conn): pass
    def on_pong(self, conn, message): pass
    def on_reject(self, conn, message): pass
    def on_sendcmpct(self, conn, message): pass
    def on_sendheaders(self, conn, message): pass
    def on_tx(self, conn, message): pass

    # Message receiving helper functions

    def sync(self, test_function, timeout=60):
        while timeout > 0:
            with mininode_lock:
                if test_function():
                    return
            time.sleep(0.05)
            timeout -= 0.05
        raise AssertionError("Sync failed to complete")
        
    def wait_for_block(self, blockhash, timeout=60):
        test_function = lambda: self.last_message.get("block") and self.last_message["block"].block.rehash() == blockhash
        self.sync(test_function, timeout)

    def wait_for_getdata(self, timeout=60):
        test_function = lambda: self.last_message.get("getdata")
        self.sync(test_function, timeout)

    def wait_for_getheaders(self, timeout=60):
        test_function = lambda: self.last_message.get("getheaders")
        self.sync(test_function, timeout)

    def wait_for_inv(self, expected_inv, timeout=60):
        test_function = lambda: self.last_message.get("inv") and self.last_message["inv"] != expected_inv
        self.sync(test_function, timeout)

    def wait_for_verack(self, timeout=60):
        """Spin until verack message has been received from node.

        Tests may want to use this as a signal that the test can begin.
        This can be called from the testing thread, so it needs to acquire the
        global lock.
        """
        test_function = lambda: self.message_count["verack"]
        self.sync(test_function, timeout)

    # Message sending helper functions

    def send_message(self, message):
        if self.connection:
            self.connection.send_message(message)
        else:
            print("Cannot send message. No connection to node!")

    def send_and_ping(self, message):
        self.send_message(message)
        self.sync_with_ping()

    # Sync up with the node
    def sync_with_ping(self, timeout=60):
        self.send_message(msg_ping(nonce=self.ping_counter))
        test_function = lambda: self.last_message.get("pong") and self.last_message["pong"].nonce == self.ping_counter
        success = wait_until(test_function, timeout = timeout)
        self.ping_counter += 1
        return success

class RejectResult(object):
    """Outcome that expects rejection of a transaction or block."""
    def __init__(self, code, reason=b''):
        self.code = code
        self.reason = reason
    def match(self, other):
        if self.code != other.code:
            return False
        return other.reason.startswith(self.reason)
    def __repr__(self):
        return '%i:%s' % (self.code,self.reason or '*')

class NodeConnWithStoreCB(NodeConnCB):
    """A NodeConnCB with transaction and block store.

    NodeConnWithStoreCB behaves as follows:

    on_inv: log the message but don't request
    on_headers: log the chain tip
    on_pong: update ping response map (for synchronization)
    on_getheaders: provide headers via BlockStore
    on_getdata: provide blocks via BlockStore
    """

    def __init__(self, block_store, tx_store):
        super().__init__()
        self.connection = None
        self.bestblockhash = None
        self.block_store = block_store
        self.block_request_map = {}
        self.tx_store = tx_store
        self.tx_request_map = {}
        self.block_reject_map = {}
        self.tx_reject_map = {}

        # When the pingmap is non-empty we're waiting for 
        # a response
        self.pingMap = {} 
        self.lastInv = []

    def on_headers(self, conn, message):
        if len(message.headers) > 0:
            best_header = message.headers[-1]
            best_header.calc_sha256()
            self.bestblockhash = best_header.sha256

    def on_getheaders(self, conn, message):
        response = self.block_store.headers_for(message.locator, message.hashstop)
        if response is not None:
            conn.send_message(response)

    def on_getdata(self, conn, message):
        [conn.send_message(r) for r in self.block_store.get_blocks(message.inv)]
        [conn.send_message(r) for r in self.tx_store.get_transactions(message.inv)]

        for i in message.inv:
            if i.type == 1:
                self.tx_request_map[i.hash] = True
            elif i.type == 2:
                self.block_request_map[i.hash] = True

    def on_inv(self, conn, message):
        self.lastInv = [x.hash for x in message.inv]

    def on_pong(self, conn, message):
        try:
            del self.pingMap[message.nonce]
        except KeyError:
            raise AssertionError("Got pong for unknown ping [%s]" % repr(message))

    def on_reject(self, conn, message):
        if message.message == b'tx':
            self.tx_reject_map[message.data] = RejectResult(message.code, message.reason)
        if message.message == b'block':
            self.block_reject_map[message.data] = RejectResult(message.code, message.reason)

    def send_inv(self, obj):
        mtype = 2 if isinstance(obj, CBlock) else 1
        self.connection.send_message(msg_inv([CInv(mtype, obj.sha256)]))

    def send_getheaders(self):
        # We ask for headers from their last tip.
        m = msg_getheaders()
        m.locator = self.block_store.get_locator(self.bestblockhash)
        self.connection.send_message(m)

    def send_header(self, header):
        m = msg_headers()
        m.headers.append(header)
        self.connection.send_message(m)

    # This assumes BIP31
    def send_ping(self, nonce):
        self.pingMap[nonce] = True
        self.connection.send_message(msg_ping(nonce))

    def received_ping_response(self, nonce):
        return nonce not in self.pingMap

    def send_mempool(self):
        self.lastInv = []
        self.connection.send_message(msg_mempool())

# The actual NodeConn class
# This class provides an interface for a p2p connection to a specified node
class NodeConn(asyncore.dispatcher):
    messagemap = {
        b"version": msg_version,
        b"verack": msg_verack,
        b"addr": msg_addr,
        b"alert": msg_alert,
        b"inv": msg_inv,
        b"getdata": msg_getdata,
        b"getblocks": msg_getblocks,
        b"tx": msg_tx,
        b"block": msg_block,
        b"getaddr": msg_getaddr,
        b"ping": msg_ping,
        b"pong": msg_pong,
        b"headers": msg_headers,
        b"getheaders": msg_getheaders,
        b"reject": msg_reject,
        b"mempool": msg_mempool,
        b"feefilter": msg_feefilter,
        b"sendheaders": msg_sendheaders,
        b"sendcmpct": msg_sendcmpct,
        b"cmpctblock": msg_cmpctblock,
        b"getblocktxn": msg_getblocktxn,
        b"blocktxn": msg_blocktxn
    }
    MAGIC_BYTES = {
        "mainnet": b"\xf9\xbe\xb4\xd9",   # mainnet
        "testnet3": b"\x0b\x11\x09\x07",  # testnet3
        "regtest": b"\xfa\xbf\xb5\xda",   # regtest
    }

    def __init__(self, dstaddr, dstport, rpc, callback, net="regtest", services=NODE_NETWORK, send_version=True):
        asyncore.dispatcher.__init__(self, map=mininode_socket_map)
        self.log = logging.getLogger("NodeConn(%s:%d)" % (dstaddr, dstport))
        self.dstaddr = dstaddr
        self.dstport = dstport
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sendbuf = b""
        self.recvbuf = b""
        self.ver_send = 209
        self.ver_recv = 209
        self.last_sent = 0
        self.state = "connecting"
        self.network = net
        self.cb = callback
        self.disconnect = False
        self.nServices = 0

        if send_version:
            # stuff version msg into sendbuf
            vt = msg_version()
            vt.nServices = services
            vt.addrTo.ip = self.dstaddr
            vt.addrTo.port = self.dstport
            vt.addrFrom.ip = "0.0.0.0"
            vt.addrFrom.port = 0
            self.send_message(vt, True)

        print('MiniNode: Connecting to Bitcoin Node IP # ' + dstaddr + ':' \
            + str(dstport))

        try:
            self.connect((dstaddr, dstport))
        except:
            self.handle_close()
        self.rpc = rpc

    def show_debug_msg(self, msg):
        self.log.debug(msg)

    def handle_connect(self):
        if self.state != "connected":
            self.show_debug_msg("MiniNode: Connected & Listening: \n")
            self.state = "connected"
            self.cb.on_open(self)

    def handle_close(self):
        self.show_debug_msg("MiniNode: Closing Connection to %s:%d... "
                            % (self.dstaddr, self.dstport))
        self.state = "closed"
        self.recvbuf = b""
        self.sendbuf = b""
        try:
            self.close()
        except:
            pass
        self.cb.on_close(self)

    def handle_read(self):
        try:
            t = self.recv(8192)
            if len(t) > 0:
                self.recvbuf += t
                self.got_data()
        except:
            pass

    def writable(self):
        with mininode_lock:
            pre_connection = self.state == "connecting"
            length = len(self.sendbuf)
        return (length > 0 or pre_connection)

    def handle_write(self):
        with mininode_lock:
            # asyncore does not expose socket connection, only the first read/write
            # event, thus we must check connection manually here to know when we
            # actually connect
            if self.state == "connecting":
                self.handle_connect()
            if not self.writable():
                return

            try:
                sent = self.send(self.sendbuf)
            except:
                self.handle_close()
                return
            self.sendbuf = self.sendbuf[sent:]

    def got_data(self):
        try:
            while True:
                if len(self.recvbuf) < 4:
                    return
                if self.recvbuf[:4] != self.MAGIC_BYTES[self.network]:
                    raise ValueError("got garbage %s" % repr(self.recvbuf))
                if self.ver_recv < 209:
                    if len(self.recvbuf) < 4 + 12 + 4:
                        return
                    command = self.recvbuf[4:4+12].split(b"\x00", 1)[0]
                    msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
                    checksum = None
                    if len(self.recvbuf) < 4 + 12 + 4 + msglen:
                        return
                    msg = self.recvbuf[4+12+4:4+12+4+msglen]
                    self.recvbuf = self.recvbuf[4+12+4+msglen:]
                else:
                    if len(self.recvbuf) < 4 + 12 + 4 + 4:
                        return
                    command = self.recvbuf[4:4+12].split(b"\x00", 1)[0]
                    msglen = struct.unpack("<i", self.recvbuf[4+12:4+12+4])[0]
                    checksum = self.recvbuf[4+12+4:4+12+4+4]
                    if len(self.recvbuf) < 4 + 12 + 4 + 4 + msglen:
                        return
                    msg = self.recvbuf[4+12+4+4:4+12+4+4+msglen]
                    th = sha256(msg)
                    h = sha256(th)
                    if checksum != h[:4]:
                        raise ValueError("got bad checksum " + repr(self.recvbuf))
                    self.recvbuf = self.recvbuf[4+12+4+4+msglen:]
                if command in self.messagemap:
                    f = BytesIO(msg)
                    t = self.messagemap[command]()
                    t.deserialize(f)
                    self.got_message(t)
                else:
                    self.show_debug_msg("Unknown command: '" + command + "' " +
                                        repr(msg))
        except Exception as e:
            print('got_data:', repr(e))
            # import  traceback
            # traceback.print_tb(sys.exc_info()[2])

    def send_message(self, message, pushbuf=False):
        if self.state != "connected" and not pushbuf:
            raise IOError('Not connected, no pushbuf')
        self.show_debug_msg("Send %s" % repr(message))
        command = message.command
        data = message.serialize()
        tmsg = self.MAGIC_BYTES[self.network]
        tmsg += command
        tmsg += b"\x00" * (12 - len(command))
        tmsg += struct.pack("<I", len(data))
        if self.ver_send >= 209:
            th = sha256(data)
            h = sha256(th)
            tmsg += h[:4]
        tmsg += data
        with mininode_lock:
            self.sendbuf += tmsg
            self.last_sent = time.time()

    def got_message(self, message):
        if message.command == b"version":
            if message.nVersion <= BIP0031_VERSION:
                self.messagemap[b'ping'] = msg_ping_prebip31
        if self.last_sent + 30 * 60 < time.time():
            self.send_message(self.messagemap[b'ping']())
        self.show_debug_msg("Recv %s" % repr(message))
        self.cb.deliver(self, message)

    def disconnect_node(self):
        self.disconnect = True


class NetworkThread(Thread):
    def run(self):
        while mininode_socket_map:
            # We check for whether to disconnect outside of the asyncore
            # loop to workaround the behavior of asyncore when using
            # select
            disconnected = []
            for fd, obj in mininode_socket_map.items():
                if obj.disconnect:
                    disconnected.append(obj)
            [ obj.handle_close() for obj in disconnected ]
            asyncore.loop(0.1, use_poll=True, map=mininode_socket_map, count=1)


# An exception we can raise if we detect a potential disconnect
# (p2p or rpc) before the test is complete
class EarlyDisconnectError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
