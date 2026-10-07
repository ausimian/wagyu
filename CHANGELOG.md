# Changelog

This file records all notable changes to this project.

<!-- %% CHANGELOG_ENTRIES %% -->

## 0.3.0 - 2026-10-07

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

## 0.2.1 - 2026-10-04

### Changed

- The README and the documentation for `Wagyu`, `Wagyu.Config` and
  `Wagyu.Config.Peer` are rewritten in Simplified Technical English (ASD-STE100):
  shorter sentences, and lists for conditions, errors and options.

### Fixed

- The `Wagyu.Config` documentation now says that the `:invalid` reason also
  covers values that are not allowed, such as a multicast address.

## 0.2.0 - 2026-09-29

The first release of Wagyu, a user-mode WireGuard endpoint for `:gen_tcp` and
`:gen_udp` sockets. An Elixir application can reach hosts on a WireGuard
network without root, a kernel module or a TUN device, and without changing
how the rest of the node connects.

### Added

- `Wagyu.start_link/1`, or `{Wagyu, options}` in a supervision tree, starts an
  interface with its own UDP socket and SmolNet stack. `Wagyu.stack/1` returns
  the stack to open sockets on, `Wagyu.info/1` reports counters and peer
  state, and `Wagyu.stop/1` stops the interface.
- TCP and UDP sockets opened on the stack reach peers through the tunnel, over
  IPv4 and IPv6, with each packet routed to a peer by its AllowedIPs. `:ssl`
  connections run over the same TCP sockets, and the README shows a client.
- WireGuard handshakes in both directions, preshared keys and roaming
  endpoints, with rekeying, retries and keepalives on WireGuard's timers,
  interoperating with wireguard-go.
- Replay protection, and cookie replies with per-source rate limits for
  handshakes under load.
- `Wagyu.Config.new/1` validates options: up to 1024 peers, an MTU from 1280
  to 65,475 (default 1420) and up to 512 sockets per stack (default 64).
  Errors name the offending option and never include its value.
- Bounded queues throughout, with drops counted in `Wagyu.info/1`. TCP slows
  down, rather than losing segments inside the interface, when peers cannot
  keep up.
- Runs on Elixir 1.18 or later with SmolNet 0.7, on macOS on Apple silicon or
  Linux (glibc) on x86_64 or ARM64.
