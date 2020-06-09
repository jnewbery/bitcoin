#### Change in automatic banning

Automatic banning of peers for bad behavior has been slightly altered:

- automatic bans will no longer time out automatically after 24 hours.
  Depending on traffic from other peers, automatic bans may time out at an
  indeterminate time.

- automatic bans will no longer be persisted over restarts. Only manual bans
  will be persisted.

- automatic bans will no longer be returned by the `listbanned` RPC.

- automatic bans can no longer be lifted with the `setban remove` RPC command.
  If you need to remove an automatic ban, you can clear all bans (including
  manual bans) with the `clearbanned` RPC, or stop-start to clear automatic bans.

- automatic bans are now referred to as discouraged nodes in log output, as
  they're not (and weren't) strictly banned: incoming connections are still
  allowed from them, but they're preferred for eviction.
