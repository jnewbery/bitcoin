#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for bitcoind node under test"""

import decimal
import errno
import http.client
import logging
import os
import subprocess
import time

from .util import (
    assert_equal,
    get_rpc_proxy,
    rpc_url,
)
from .authproxy import JSONRPCException
from .errors import CLIRPCException

class TestNode():
    """A class for representing a bitcoind node under test.

    This class contains:

    - state about the node (whether it's running, etc)
    - a Python subprocess.Popen object representing the running process
    - an RPC connection to the node

    To make things easier for the test writer, a bit of magic is happening under the covers.
    Any unrecognised messages will be dispatched to the RPC connection."""

    def __init__(self, i, dirname, extra_args, rpchost, timewait, binary, stderr, mocktime, coverage_dir, use_cli=False):
        self.index = i
        self.datadir = os.path.join(dirname, "node" + str(i))
        self.rpchost = rpchost
        self.rpc_timeout = timewait
        if binary is None:
            self.binary = os.getenv("BITCOIND", "bitcoind")
        else:
            self.binary = binary
        self.stderr = stderr
        self.coverage_dir = coverage_dir
        # Most callers will just need to add extra args to the standard list below. For those callers that need more flexibity, they can just set the args property directly.
        self.extra_args = extra_args
        self.args = [self.binary, "-datadir=" + self.datadir, "-server", "-keypool=1", "-discover=0", "-rest", "-logtimemicros", "-debug", "-debugexclude=libevent", "-debugexclude=leveldb", "-mocktime=" + str(mocktime), "-uacomment=testnode%d" % i]

        self.cli = TestNodeCLI(os.getenv("BITCOINCLI", "bitcoin-cli"), self.datadir)
        self.use_cli = use_cli

        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc = None
        self.url = None
        self.log = logging.getLogger('TestFramework.node%d' % i)

    def __getattr__(self, *args, **kwargs):
        """Dispatches any unrecognised messages to CLI or the RPC connection."""
        if self.use_cli:
            return self.cli.__getattr__(*args, **kwargs)
        else:
            assert self.rpc_connected and self.rpc is not None, "Error: no RPC connection"
            return self.rpc.__getattr__(*args, **kwargs)

    def start(self):
        """Start the node."""
        # import pdb; pdb.set_trace()
        self.process = subprocess.Popen(self.args + self.extra_args, stderr=self.stderr)
        self.running = True
        self.log.debug("bitcoind started, waiting for RPC to come up")

    def wait_for_rpc_connection(self):
        """Sets up an RPC connection to the bitcoind process. Returns False if unable to connect."""

        attempts = 40
        while attempts > 0:
            assert not self.process.poll(), "bitcoind exited with status %i during initialization" % self.process.returncode
            try:
                self.rpc = get_rpc_proxy(rpc_url(self.datadir, self.index, self.rpchost), self.index)
                self.rpc.getblockcount()
                # If the call to getblockcount() succeeds then the RPC connection is up
                self.rpc_connected = True
                self.url = self.rpc.url
                self.log.debug("RPC successfully started")
                return True
            except IOError as e:
                if e.errno != errno.ECONNREFUSED:  # Port not yet open?
                    raise  # unknown IO error
            except JSONRPCException as e:  # Initialization phase
                if e.error['code'] != -28:  # RPC in warmup?
                    raise  # unknown JSON RPC exception
            except ValueError as e:  # cookie file not found and no rpcuser or rpcassword. bitcoind still starting
                if "No RPC credentials" not in str(e):
                    raise
            time.sleep(0.25)
            attempts -= 1
        raise AssertionError("Unable to connect to bitcoind")

    def stop_node(self):
        """Stop the node."""
        if not self.running:
            return
        self.log.debug("Stopping node")
        try:
            self.stop()
        except http.client.CannotSendRequest as e:
            self.log.exception("Unable to stop node.")

    def is_node_stopped(self):
        """Checks whether the node has stopped.

        Returns True if the node has stopped. False otherwise.
        This method is responsible for freeing resources (self.process)."""
        if not self.running:
            return True
        return_code = self.process.poll()
        if return_code is not None:
            # process has stopped. Assert that it didn't return an error code.
            assert_equal(return_code, 0)
            self.running = False
            self.process = None
            self.log.debug("Node stopped")
            return True
        return False

    def node_encrypt_wallet(self, passphrase):
        """"Encrypts the wallet.

        This causes bitcoind to shutdown, so this method takes
        care of cleaning up resources."""
        self.encryptwallet(passphrase)
        while not self.is_node_stopped():
            time.sleep(0.1)
        self.rpc = None
        self.rpc_connected = False

class TestNodeCLI():
    """Interface to bitcoin-cli for an individual node"""

    def __init__(self, binary, datadir):
        self.binary = binary
        self.datadir = datadir
        self.log = logging.getLogger('TestFramework.bitcoincli')

    def __getattr__(self, command):
        def dispatcher(*args, **kwargs):
            return self.send_cli(command, *args, **kwargs)
        return dispatcher

    def send_cli(self, rpc_func, *args, **kwargs):
        """Run bitcoin-cli command. Deserializes returned string as python object."""

        import simplejson as json
        pos_args = []
        for arg in args:
            if isinstance(arg, str):
                pos_args.append(' "%s"' % arg)
            else:
                pos_args.append(json.dumps(json.dumps(arg)))
        named_args = []
        for arg in kwargs.items():
            if isinstance(arg[1], str):
                named_args.append("%s=%s" % (str(arg[0]), str(arg[1])))
            else:
                named_args.append("%s=%s" % (str(arg[0]), json.dumps(json.dumps(arg[1]))))
        assert not (pos_args and named_args), "Cannot use positional arguments and named arguments in the same bitcoin-cli call"
        command = self.binary + " -datadir=" + self.datadir
        if named_args:
            command += " -named"
        command += " %s %s %s" % (rpc_func, " ".join(pos_args), " ".join(named_args))

        self.log.debug("Running bitcoin-cli command: %s" % command)
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        if process.returncode != 0:
            stderr_lines = process.stderr.split("\n")
            if len(stderr_lines) > 2:
                error_message = stderr_lines[2].rstrip()
            else:
                error_message = process.stderr
            raise CLIRPCException({'code': 0 - int(process.returncode), 'message': error_message})
        try:
            return json.loads(process.stdout, parse_float=decimal.Decimal)
        except json.decoder.JSONDecodeError:
            # bitcoin-cli can return JSON objects or strings. Deal with strings here
            ret_string = process.stdout.rstrip()
            if ret_string == "":
                return None
            else:
                return ret_string
