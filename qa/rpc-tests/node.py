#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Base class for a test bitcoin node."""

import logging
import optparse
import os
import shutil
import sys
import tempfile
import traceback

from .authproxy import JSONRPCException
from .util import (PortSeed,
                   check_json_precision,
                   connect_nodes_bi,
                   enable_coverage,
                   initialize_chain_clean,
                   initialize_chain,
                   start_nodes,
                   stop_node,
                   stop_nodes,
                   sync_blocks,
                   sync_mempools)

class Node():
    """A representation of a bitcoind node.

    This class represents our view of a bitcoind node and contains useful state
    and methods to interact with that node.
    
	Attributes:
		p2p_conns: a list of P2PConn objects representing P2P connections to the node
		p2p_ever_connected: a boolean latch, indicating whether we have ever created a P2P connection to the node
    """

	def __init__(self, ip_addr):
		self.p2p_conns = []

		self.p2p_ever_connected = False

        self.ip_addr = ip_addr

    def add_connection()
        
