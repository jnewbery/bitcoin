(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Bitcoin Core version *version* is now available from:

  <https://bitcoin.org/bin/bitcoin-core-*version*/>

This is a new major version release, including new features, various bugfixes
and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on Mac)
or `bitcoind`/`bitcoin-qt` (on Linux).

The first time you run version 0.15.0, your chainstate database will be converted to a
new format, which will take anywhere from a few minutes to half an hour,
depending on the speed of your machine.

Note that the block database format also changed in version 0.8.0 and there is no
automatic upgrade code from before version 0.8 to version 0.15.0. Upgrading
directly from 0.7.x and earlier without redownloading the blockchain is not supported.
However, as usual, old wallet versions are still supported.

Downgrading warning
-------------------

The chainstate database for this release is not compatible with previous
releases, so if you run 0.15 and then decide to switch back to any
older version, you will need to run the old release with the `-reindex-chainstate`
option to rebuild the chainstate data structures in the old format.

If your node has pruning enabled, this will entail re-downloading and
processing the entire blockchain.

Compatibility
==============

Bitcoin Core is extensively tested on multiple operating systems using
the Linux kernel, macOS 10.8+, and Windows Vista and later. Windows XP is not supported.

Bitcoin Core should also work on most other Unix-like systems but is not
frequently tested on them.

Notable changes
===============

GCC 4.8.x
--------------
The minimum version of GCC required to compile Bitcoin Core is now 4.8. No effort will be
made to support older versions of GCC. See discussion in issue #11732 for more information.

HD-wallets by default
---------------------
Due to a backward-incompatible change in the wallet database, wallets created
with version 0.16.0 will be rejected by previous versions. Also, version 0.16.0
will only create hierarchical deterministic (HD) wallets.

Replace-By-Fee by default in GUI
--------------------------------
The send screen now uses BIP-125 RBF by default, regardless of `-walletrbf`.
There is a checkbox to mark the transaction as final.

The RPC default remains unchanged: to use RBF, launch with `-walletrbf=1` or
use the `replaceable` argument for individual transactions.

Wallets directory configuration (`-walletdir`)
----------------------------------------------

Bitcoin Core now has more flexibility in where the wallets directory can be located.

- For new installations (where the data directory doesn't already exist),
  wallets will now be stored in a new `wallets/` subdirectory inside the data
  directory by default.
- For existing nodes (where the data directory already exists), wallets will be
  stored in the data directory root by default. If a `wallets/` subdirectory
  already exists in the data directory root, then wallets will be stored in the
  `wallets/` subdirectory by default.
- The location of the wallets directory can be overridden by specifying a
  `-walletdir=<path>` option where `<path>` can be an absolute path or a
  relative path (relative to the current working directory). `<path>` can
  also be a path to symlink to a directory.

Wallet configuration (`-wallet`)
--------------------------------

The `-wallet` argument now accepts full paths instead of requiring wallets
to be located in the wallets directory. The `-wallet` argument can be an
absolute path or a relative path (relative to the wallets directory).

- if the `-wallet` argument specifies a path that does not exist, Bitcoin
  Core will create a wallet directory at the specified location (containing a
  wallet.dat data file, a db.log file, and database/log.?????????? files).
- if the `-wallet` argument specifies a directory containing a wallet.dat
  file (or a symlink to a directory containing a wallet.dat file), Bitcoin
  Core will use that directory as a wallet directory
- for backwards compatibility, if the `-wallet` argument specifies an existing
  wallet data file, Bitcoin Core will use that file as the wallet data file
  and the parent of that file as the wallet directory.

If Bitcoin Core is running with multiple wallets, the wallet name must be specified
when accessing a wallet over RPC (in the URI endpoint) or bitcoin-cli (in the
`-rpcwallet` argument). The name should be specified exactly as written in the
`-wallet` argument.

This should make backing up wallets more straightforward than
before because the specified wallet path can just be directly archived without
having to look in the parent directory for transaction log files.

Care should be taken when choosing wallet locations on external storage, since
funds may be lost if a wallet database becomes unavailable during operation.

Low-level RPC changes
----------------------
- The deprecated RPC `getinfo` was removed. It is recommended that the more specific RPCs are used:
  * `getblockchaininfo`
  * `getnetworkinfo`
  * `getwalletinfo`
  * `getmininginfo`
- The wallet RPC `getreceivedbyaddress` will return an error if called with an address not in the wallet.
- When bitcoin is not started with any `-wallet=<path>` options, the name of
  the default wallet returned by `getwalletinfo` and `listwallets` RPCs is
  now the empty string `""` instead of `"wallet.dat"`. If bitcoin is started
  with any `-wallet=<path>` options, there is no change in behavior, and the
  name of any wallet is just its `<path>` string.

Changed command-line options
-----------------------------
- `-debuglogfile=<file>` can be used to specify an alternative debug logging file.

Renamed script for creating JSON-RPC credentials
-----------------------------
The `share/rpcuser/rpcuser.py` script was renamed to `share/rpcauth/rpcauth.py`. This script can be
used to create `rpcauth` credentials for a JSON-RPC user.


- `dumpwallet` now includes hex-encoded scripts from the wallet in the dumpfile, and
  `importwallet` now imports these scripts, but corresponding addresses may not be added
  correctly or a manual rescan may be required to find relevant transactions.

Credits
=======

Thanks to everyone who directly contributed to this release:


As well as everyone that helped translating on [Transifex](https://www.transifex.com/projects/p/bitcoin/).
