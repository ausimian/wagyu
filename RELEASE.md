The first release of Wagyu, a user-mode WireGuard endpoint for `:gen_tcp` and
`:gen_udp` sockets. An Elixir application can reach hosts on a WireGuard
network without root, a kernel module or a TUN device, and without changing
how the rest of the node connects. An interface's configuration cannot change
while it runs.

### Added

- `Wagyu.start_link/1`, or `{Wagyu, options}` in a supervision tree, starts an
  interface with its own UDP socket and SmolNet stack. `Wagyu.stack/1` returns
  the stack to open sockets on, `Wagyu.info/1` reports counters and peer
  state, and `Wagyu.stop/1` stops the interface.
- TCP and UDP sockets opened on the stack reach peers through the tunnel, over
  IPv4 and IPv6, with each packet routed to a peer by its AllowedIPs.
- WireGuard handshakes in both directions, preshared keys, rekeying, retries,
  keepalives, persistent keepalives and roaming endpoints on WireGuard's
  timers, interoperating with wireguard-go.
- Replay protection, and cookie replies with per-source rate limits for
  handshakes under load.
- `Wagyu.Config.new/1` validates options: up to 1024 peers, an MTU from 1280
  to 65,475 (default 1420) and up to 512 sockets per stack (default 64).
  Errors name the offending option and never include its value.
- Bounded queues throughout, with drops counted in `Wagyu.info/1`. TCP slows
  down, rather than losing segments inside the interface, when peers cannot
  keep up.
- Private and preshared keys stay out of logs, crash reports and
  `Wagyu.info/1`.
- Runs on Elixir 1.18 or later, on macOS on Apple silicon or Linux (glibc) on
  x86_64 or ARM64.
