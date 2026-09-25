# Wagyu

Wagyu is a user-mode [WireGuard](https://www.wireguard.com/) endpoint for
[SmolNet](https://github.com/ausimian/smolnet) application sockets, written in
Elixir. It carries IPv4 and IPv6 packets between a SmolNet network stack and
WireGuard peers over one UDP socket, with no host TUN device.

> **Status:** Wagyu is under development and not yet on Hex. An interface
> starts under supervision with its UDP socket and SmolNet stack, completes
> WireGuard handshakes with its configured peers in both directions, and
> carries TCP and UDP traffic for sockets on its stack, interoperating with
> wireguard-go. Handshake retries, rekeys and keepalives on timers are not
> implemented yet, so a key is used for at most 180 seconds and the next
> packet then starts a new handshake. Progress is tracked in
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

Wagyu is not on Hex yet, so add it from GitHub:

```elixir
def deps do
  [
    {:wagyu, github: "ausimian/wagyu"}
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

### Connect through the tunnel with `:gen_tcp`

`Wagyu.stack/1` returns the interface's network stack. Pass it, together with
SmolNet's TCP module, in the options of an ordinary `:gen_tcp` call, and that
socket's traffic goes through the tunnel:

```elixir
{:ok, stack} = Wagyu.stack(:wg0)

options = [
  {:tcp_module, SmolNet.Inet.Tcp},
  {:smolnet_stack, stack},
  :inet,
  :binary,
  {:active, false}
]

{:ok, socket} = :gen_tcp.connect({10, 13, 0, 1}, 443, options, 5_000)
:ok = :gen_tcp.send(socket, "hello")
{:ok, reply} = :gen_tcp.recv(socket, 0, 5_000)
:ok = :gen_tcp.close(socket)
```

The options apply to that socket only; the node's other TCP connections are
unaffected. For IPv6, use `SmolNet.Inet6.Tcp` with `:inet6`. The destination
must be reachable through the stack's routes and a peer's `allowed_ips`.

`Wagyu.info/1` reports counters and peer state, and `Wagyu.stop/1` stops the
interface. The `Wagyu` and `Wagyu.Config` module documentation covers every
option, names and handles, failure and restart behaviour, and the limits on
queued work.

## License

MIT. See [LICENSE](LICENSE).

Working on Wagyu itself? See
[MAINTAINING.md](https://github.com/ausimian/wagyu/blob/main/MAINTAINING.md).
