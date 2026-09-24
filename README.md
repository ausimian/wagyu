# Wagyu

Wagyu is a user-mode WireGuard endpoint for
[SmolNet](https://github.com/ausimian/smolnet) application sockets, written in
Elixir. It carries IPv4 and IPv6 packets between a SmolNet network stack and
WireGuard peers over one UDP socket, with no host TUN device.

Wagyu is under development. An interface starts under supervision with its
UDP socket and SmolNet stack (`Wagyu.start_link/1`), validates its
configuration, and completes WireGuard handshakes with its configured peers,
initiating on outbound traffic and responding to initiations, including with
wireguard-go. The encrypted data path is not implemented yet, so no traffic
crosses the tunnel.

## Development

Use Elixir 1.19.5 and Erlang/OTP 28.3 locally. The project supports Elixir
1.18 and newer on compatible OTP releases.

```sh
mix deps.get
mix precommit
```

`mix precommit` compiles with warnings treated as errors, checks dependency
usage and formatting, runs Credo, and executes the tests.

The interoperability tests (tagged `interop`) run Wagyu against
[wireguard-go](https://git.zx2c4.com/wireguard-go) on its userspace network
stack, which needs no TUN device or root. They build a small Go helper in
`test/interop`, so they run when `go` (1.25 or later) is on the `PATH` and
are skipped otherwise. `mix test --exclude interop` skips them regardless.
