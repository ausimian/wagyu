### Added

- `Wagyu.Config.new/1` validates interface options: a 32-byte private key,
  the listen address, SmolNet stack options (MTU 1280 to 65,475, default 1420;
  at most 8 addresses and 4 routes), and up to 1024 peers with their public
  keys, endpoints and AllowedIPs. Errors name the offending option, and the
  configuration's `Inspect` implementation omits private and preshared keys.
- A nonzero preshared key fails validation with
  `{:error, :unsupported_preshared_key}` instead of being treated as zero.
- `Wagyu.start_link/1`, or `{Wagyu, options}` in a supervision tree, starts
  an interface: a UDP socket on the listen address and a SmolNet stack whose
  reference `Wagyu.stack/1` returns for opening sockets. `Wagyu.info/1`
  reports counters, peer state and public keys, and `Wagyu.stop/1` stops the
  interface, its socket and its stack. All three accept the interface's PID
  or its registered name. WireGuard handshakes are not complete yet, so no
  traffic crosses the tunnel: arriving datagrams are checked and dropped,
  and packets sent on the stack are routed to their peer and dropped there.
- An interface authenticates WireGuard handshake initiations and identifies
  the configured peer that sent each one, but does not respond to them yet.
  It refuses, silently, initiations from unknown keys, replayed or stale
  timestamps (including after a peer's process restarts), and a second
  initiation from one peer within 20 ms, as wireguard-go and Linux do.
  `Wagyu.info/1` counts each outcome. Handshake cryptography runs in at
  most 8 workers, off the socket's receive path, and at most 2 accepted
  handshakes wait for each peer.
- Responses, cookie replies and transport messages are delivered only to
  the peer holding their receiver index. Indices are random and unique, and
  one that is retired, or whose peer has exited, drops at the interface
  and is not reused for 180 seconds.
- Wagyu now depends on Decibel 1.1.1 or later.
- If the stack fails, including when stopped with `SmolNet.stop_stack/1`,
  the interface restarts with a new stack and sockets opened on the old one
  must be reopened. Any other failure inside the interface keeps the stack
  and its open sockets.
- Every queue between an interface's processes is bounded, and whatever
  does not fit is dropped and counted in `Wagyu.info/1` rather than queued.
  The SmolNet stack's outbound packets are the exception: SmolNet sends them
  without backpressure, so the interface drains them promptly and drops what
  its queue cannot take.
- Private and preshared keys stay out of logs: child specs and supervisors
  hold the validated configuration rather than the raw options, and
  processes that hold keys redact them from their status and crash reports.
- `child_spec/1` raises `ArgumentError` for invalid options, naming the
  validation error without the options' values.
- Internal WireGuard building blocks for the interface to come: message
  encoding and decoding that rejects malformed datagrams without raising,
  keyed BLAKE2s and MAC1, wall-clock TAI64N timestamps, IP header validation
  for decrypted packets, and longest-prefix AllowedIPs routing.
