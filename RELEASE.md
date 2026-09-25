### Added

- `Wagyu.Config.new/1` validates interface options: a 32-byte private key,
  the listen address, SmolNet stack options (MTU 1280 to 65,475, default 1420;
  at most 8 addresses and 4 routes), and up to 1024 peers with their public
  keys, endpoints and AllowedIPs. A peer public key that no handshake can
  use, such as 32 zero bytes or another low-order point, is rejected. Errors
  name the offending option, and the configuration's `Inspect`
  implementation omits private and preshared keys.
- A nonzero preshared key fails validation with
  `{:error, :unsupported_preshared_key}` instead of being treated as zero.
- `Wagyu.start_link/1`, or `{Wagyu, options}` in a supervision tree, starts
  an interface: a UDP socket on the listen address and a SmolNet stack whose
  reference `Wagyu.stack/1` returns for opening sockets. `Wagyu.info/1`
  reports counters, peer state and public keys, and `Wagyu.stop/1` stops the
  interface, its socket and its stack. All three accept the interface's PID
  or its registered name.
- TCP and UDP sockets opened on an interface's stack exchange data with its
  peers through the tunnel, interoperating with wireguard-go, over IPv4 and
  IPv6. A packet goes to the peer whose AllowedIPs prefix most specifically
  matches its destination, and a packet from a peer reaches the stack only
  if the most specific prefix matching its source is that peer's. Over a
  50 ms round trip, one TCP stream carries about 1 MB/s.
- A packet for a peer with no usable key waits, in order, while the peer
  starts a handshake, and goes out under the new key. At most 128 packets
  or 256 KiB wait per peer; beyond that they are dropped and counted.
- A transport message is refused before decryption when its counter was
  already accepted or is 8128 or more behind the highest accepted, and
  its counter is recorded only once it authenticates, so reordered packets
  pass and forged ones cannot shut genuine ones out. Messages that do not
  authenticate, carry a packet that is not valid IP (including one whose IP
  length exceeds the data), or come from a source outside the peer's
  AllowedIPs are dropped and counted, and none of them changes the peer's
  endpoint.
- A peer's endpoint follows the source of its authenticated keepalives and
  of data that passes those checks, as well as of its handshakes, so a peer
  that roams keeps its tunnel.
- A key is used for at most 180 seconds after its handshake, in either
  direction, and never beyond 2^64 - 2^13 - 1 messages, however much traffic
  there is and whatever the system clock does; it is then discarded and its
  index retired. An initiator counts those seconds from its initiation, so a
  response that arrives too late cannot leave it sending under a key the
  responder has already retired.
- Keys are replaced before they expire, as in WireGuard: the initiator of a
  handshake starts a new one when it sends under a key 120 seconds old, or
  when it receives under one 165 seconds old, and either side does after
  2^60 messages.
- An unanswered handshake initiation is retried every 5 seconds plus up to
  333 ms of random jitter, for 90 seconds from the last packet that had to
  wait for it, from the same peer process. Then the packets waiting for it
  are dropped, and `Wagyu.info/1` counts the attempt in
  `:handshakes_abandoned`.
- A peer that has received data and sent nothing for 10 seconds sends a
  keepalive, and one that has sent data and heard nothing for 15 seconds
  starts a new handshake. Otherwise idle peers stay quiet.
- A peer's `:persistent_keepalive` option, in seconds, sends a keepalive
  whenever that long passes with no traffic in either direction, to keep
  NAT mappings open. A peer with one starts with the interface.
- 540 seconds after a peer's last handshake, all its keys are discarded, and
  an idle peer's process exits, to start again when it is next needed with
  the endpoint it last had, including one learned from its traffic.
- Outbound packets are padded to a multiple of 16 bytes, but never beyond the
  MTU.
- An interface completes WireGuard handshakes with its configured peers in
  both directions, interoperating with wireguard-go. A packet sent to a peer
  with no session starts a handshake, from a random registered sender index
  and with a wall-clock TAI64N timestamp that strictly increases for each
  peer, including across restarts of its process and of the interface unless
  the wall clock steps back. A peer with no configured endpoint responds to
  initiations and then uses the endpoint they came from; until it has one,
  it counts each handshake it could not start in `Wagyu.info/1`. A peer
  sends a handshake message at most once every 5 seconds.
- Each peer keeps next, current and previous keys, as wireguard-go does. The
  initiator of a handshake sends with the new keys at once and confirms
  them with the packets waiting for them, or with an empty keepalive if
  none are; the responder keeps sending with its current keys until the
  initiator's first transport message arrives under the new ones. Transport messages still authenticate under the previous
  keys, for packets delayed across a rekey. A rekey keeps the same peer
  process, and keys that leave the three slots are closed and their indices
  retired.
- A handshake response that is not for the peer's handshake in progress, or
  whose MAC1 or authentication fails, is dropped without changing the
  peer's keys or endpoint.
- `Wagyu.info/1` counts handshake initiations, responses and keepalives
  sent, responses accepted and refused, confirmed keys, transport messages
  that do not authenticate, handshakes a peer could not start for want of an
  endpoint, and failed sends, as well as packets sent and received through
  the tunnel, keepalives received, and each reason a packet was dropped.
- The interface authenticates WireGuard handshake initiations and identifies
  the configured peer that sent each one. It refuses, silently, initiations
  from unknown keys, replayed or stale timestamps (including after a peer's
  process restarts), and a second initiation from one peer within 20 ms, as
  wireguard-go and Linux do.
  `Wagyu.info/1` counts each outcome. Handshake cryptography runs in at
  most 8 workers, off the socket's receive path, and at most 2 accepted
  handshakes wait for each peer.
- Responses, cookie replies and transport messages are delivered only to
  the peer holding their receiver index. Indices are random and unique, and
  one that is retired, or whose peer has exited, drops at the interface
  and is not reused for 180 seconds.
- Wagyu now depends on Decibel 1.1.1 or later and SmolNet 0.4.1 or later.
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
