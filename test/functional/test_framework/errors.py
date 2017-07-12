#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class containing bitcoin test framework exceptions"""

class RPCException(Exception):
    """Raised when an RPC fails"""
    def __init__(self, rpc_error):
        try:
            errmsg = '%(message)s (%(code)i)' % rpc_error
        except (KeyError, TypeError):
            errmsg = ''
        super().__init__(errmsg)
        self.error = rpc_error

class CLIRPCException(RPCException):
    """Raised when a bitcoin-cli RPC fails"""
    pass

class SkipTest(Exception):
    """This exception is raised to skip a test"""
    def __init__(self, message):
        self.message = message
