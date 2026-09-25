# Wagyu

Wagyu is a user-mode [WireGuard](https://www.wireguard.com/) endpoint for
[SmolNet](https://github.com/ausimian/smolnet) application sockets, written in
Elixir. It carries IPv4 and IPv6 packets between a SmolNet network stack and
WireGuard peers over one UDP socket, with no host TUN device.

> **Status:** Wagyu is under development and not yet on Hex. An interface
> starts under supervision with its UDP socket and SmolNet stack, and completes
> WireGuard handshakes with its configured peers in both directions, including
> with wireguard-go. The encrypted data path is not implemented yet, so no
> traffic crosses the tunnel. Progress is tracked in
> [#2](https://github.com/ausimian/wagyu/issues/2).

## Why

A conventional WireGuard setup adds a TUN device to the host and routes host
traffic through it. That needs root or a kernel module, and it changes
networking for everything on the machine.

Wagyu keeps the tunnel inside the BEAM. Each interface has its own SmolNet
stack, a userspace TCP/IP stack, and only sockets opened on that stack use the
tunnel. An Elixir application can therefore reach hosts on a WireGuard network
without root, a kernel module or a TUN device, and without changing the host's
routing or how the rest of the node connects.

## How

### Requirements

- Elixir 1.18 or later.
- A platform SmolNet ships native code for: macOS on Apple silicon, or Linux
  (glibc) on x86_64 or ARM64.

### Installation

Wagyu is not on Hex yet, so add it from GitHub. Add SmolNet as well if your
application calls SmolNet directly, as the examples below do:

```elixir
def deps do
  [
    {:wagyu, github: "ausimian/wagyu"},
    {:smolnet, "~> 0.4"}
  ]
end
```

### Start an interface

`Wagyu.start_link/1` validates the configuration and starts the interface
under its own supervisor:

```elixir
{:ok, interface} =
  Wagyu.start_link(
    name: :wg0,
    private_key: local_private_key,
    listen: %{address: {0, 0, 0, 0}, port: 51820},
    stack: [
      addresses: [{{10, 13, 0, 2}, 32}],
      routes: [{{0, 0, 0, 0}, 0, {10, 13, 0, 1}}],
      mtu: 1280
    ],
    peers: [
      %{
        public_key: remote_public_key,
        endpoint: %{address: {192, 0, 2, 1}, port: 51820},
        allowed_ips: [{{0, 0, 0, 0}, 0}]
      }
    ]
  )
```

To run it in your own supervision tree instead, list `{Wagyu, options}` as a
child.

### Open sockets on its stack

`Wagyu.stack/1` returns the interface's SmolNet stack. Sockets opened on it
send their packets through the tunnel:

```elixir
{:ok, stack} = Wagyu.stack(:wg0)
{:ok, socket} = SmolNet.open(:inet, :stream, :tcp, stack: stack)
```

Standard `:gen_tcp` calls can use the stack too, one socket at a time, without
changing the node-wide TCP backend:

```elixir
options = [{:tcp_module, SmolNet.Inet.Tcp}, {:smolnet_stack, stack}, :inet, :binary, {:active, false}]
{:ok, socket} = :gen_tcp.connect({10, 13, 0, 1}, 443, options, 5_000)
```

For IPv6, use `SmolNet.Inet6.Tcp` with `:inet6`. A destination must be
reachable through the stack's routes and a peer's `allowed_ips`.

`Wagyu.info/1` reports counters and peer state, and `Wagyu.stop/1` stops the
interface. The `Wagyu` and `Wagyu.Config` module documentation covers every
option, names and handles, failure and restart behaviour, and the limits on
queued work.

## License

MIT. See [LICENSE](LICENSE).

Working on Wagyu itself? See
[MAINTAINING.md](https://github.com/ausimian/wagyu/blob/main/MAINTAINING.md).
