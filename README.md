# Wagyu

Wagyu is a user-mode WireGuard endpoint for
[SmolNet](https://github.com/ausimian/smolnet) application sockets, written in
Elixir. It carries IPv4 and IPv6 packets between a SmolNet network stack and
WireGuard peers over one UDP socket, with no host TUN device.

Wagyu is under development. An interface starts under supervision with its
UDP socket and SmolNet stack (`Wagyu.start_link/1`), validates its
configuration, and implements the WireGuard wire format: message framing,
keyed BLAKE2s MAC1, TAI64N timestamps, inner IP validation and AllowedIPs
routing. WireGuard handshakes are not implemented yet, so no traffic crosses
the tunnel.

## Development

Use Elixir 1.19.5 and Erlang/OTP 28.3 locally. The project supports Elixir
1.18 and newer on compatible OTP releases.

```sh
mix deps.get
mix precommit
```

`mix precommit` compiles with warnings treated as errors, checks dependency
usage and formatting, runs Credo, and executes the tests.
