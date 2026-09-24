### Added

- `Wagyu.Config.new/1` validates interface options: a 32-byte private key,
  the listen address, SmolNet stack options (MTU 1280 to 65,475, default 1420;
  at most 8 addresses and 4 routes), and up to 1024 peers with their public
  keys, endpoints and AllowedIPs. Errors name the offending option, and the
  configuration's `Inspect` implementation omits private and preshared keys.
- A nonzero preshared key fails validation with
  `{:error, :unsupported_preshared_key}` instead of being treated as zero.
- The `Wagyu` module documents the interface contract for `start_link/1`,
  `child_spec/1`, `stack/1`, `info/1` and `stop/1`.
- Internal WireGuard building blocks for the interface to come: message
  encoding and decoding that rejects malformed datagrams without raising,
  keyed BLAKE2s and MAC1, wall-clock TAI64N timestamps, IP header validation
  for decrypted packets, and longest-prefix AllowedIPs routing.
