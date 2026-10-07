### Added

- `Wagyu.replace_peers/2` replaces the peers of a running interface without a
  restart. The stack, the sockets and the sessions of unchanged peers stay. The
  new peer set gets the same checks and errors as the `:peers` option, and an
  invalid set changes nothing. Added peers start on demand, removed peers stop
  at once, and changes to AllowedIPs, endpoints, persistent keepalives and
  preshared keys apply to the running peers without a new handshake.
- `Wagyu.revoke_sessions/2` discards the sessions of one peer and keeps its
  configuration, for example after you rotate its preshared key. The next
  packet or handshake starts a new session.
- `Wagyu.Config.put_peers/2` validates a peer set against a configuration.
- The latest peer set survives a restart of the interface, the link or the
  stack. The interface keeps the replay timestamps of the last 1024 removed
  peers, so a captured initiation cannot be replayed after you add a peer
  again.

### Changed

- A restarted peer process uses the last endpoint that the peer learned from
  its traffic, also after a failure. Before, only a peer that stopped because
  it was idle kept that endpoint.
