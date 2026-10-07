# Wagyu

Wagyu is a user-mode [WireGuard](https://www.wireguard.com/) endpoint for
`:gen_tcp` and `:gen_udp` sockets, written in Elixir. It does not need a TUN
device, root or a kernel module. The sockets run on a userspace TCP/IP stack,
[SmolNet](https://github.com/ausimian/smolnet). Wagyu sends their packets to
WireGuard peers through one UDP socket.

## Why

A conventional WireGuard setup adds a TUN device to the host and routes the
traffic of the host through it. That setup needs root or a kernel module. It
also changes the network configuration for all programs on the machine.

Wagyu keeps the tunnel in the BEAM. Each interface has its own SmolNet stack,
which is a userspace TCP/IP stack. Only the sockets that you open on that stack
use the tunnel. Thus an Elixir application can reach hosts on a WireGuard
network without root, a kernel module or a TUN device. The routes of the host
do not change, and the other connections of the node do not change.

## How

### Requirements

- Elixir 1.18 or later.
- A platform for which SmolNet supplies native code: macOS on Apple silicon,
  or Linux (glibc) on x86_64 or ARM64.

### Installation

Add `wagyu` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:wagyu, "~> 0.2.0"}
  ]
end
```

### Keys

Keys are raw 32-byte binaries. `wg genkey`, `wg pubkey` and `wg genpsk`
print keys in base64. Decode their output:

```elixir
local_private_key = Base.decode64!("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
```

You can also make a key pair in Elixir. Give the public key to the peer as
`Base.encode64(public_key)`:

```elixir
{public_key, local_private_key} = :crypto.generate_key(:ecdh, :x25519)
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

A peer can also have a `:preshared_key`, which is the 32-byte key that
`wg genpsk` makes. The two sides must use the same preshared key.
`Wagyu.Config` describes all the options.

To change the peers of a running interface, call `Wagyu.replace_peers/2` with a
new peer set. The stack, the sockets and the sessions of unchanged peers stay.
`Wagyu.revoke_sessions/2` discards the sessions of one peer, for example after
you rotate its preshared key. To change the private key, the listen address or
the stack options, stop the interface and start it again.

To run the interface in your own supervision tree, add `{Wagyu, options}` as a
child.

### Connect through the tunnel with `:gen_tcp`

`Wagyu.stack/1` returns the network stack of the interface. Put the stack and
the TCP module of SmolNet in the options of a usual `:gen_tcp` call. The
traffic of that socket then goes through the tunnel:

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

The options apply only to that socket. The other TCP connections of the node
do not change. For IPv6, use `SmolNet.Inet6.Tcp` with `:inet6`. The routes of
the stack and the `allowed_ips` of a peer must include the destination.

### Send datagrams with `:gen_udp`

UDP works in the same way. Put the UDP module of SmolNet in the `udp_module`
option:

```elixir
options = [
  {:udp_module, SmolNet.Inet.Udp},
  {:smolnet_stack, stack},
  :inet,
  :binary,
  {:active, false}
]

{:ok, socket} = :gen_udp.open(0, options)
:ok = :gen_udp.send(socket, {10, 13, 0, 1}, 53, "query")
{:ok, {_address, _port, reply}} = :gen_udp.recv(socket, 0, 5_000)
:ok = :gen_udp.close(socket)
```

For IPv6, use `SmolNet.Inet6.Udp` with `:inet6`. The
[`:gen_udp` guide](https://hexdocs.pm/smolnet/gen_udp.html) of SmolNet
describes active mode, connected sockets and the limits on datagram size.

### Connect with `:ssl`

`:ssl` runs on the same sockets. Put the TCP module of SmolNet in the
`cb_info` option as the transport. Put the stack in the options, as for
`:gen_tcp`. The TLS options go in the same list:

```elixir
{:ok, _apps} = Application.ensure_all_started(:ssl)
{:ok, stack} = Wagyu.stack(:wg0)

options = [
  {:cb_info, {SmolNet.Inet.Tcp, :tcp, :tcp_closed, :tcp_error}},
  {:smolnet_stack, stack},
  :inet,
  :binary,
  {:active, false},
  {:verify, :verify_peer},
  {:cacerts, :public_key.cacerts_get()},
  {:server_name_indication, ~c"service.example.com"}
]

{:ok, socket} = :ssl.connect({10, 13, 0, 1}, 443, options, 5_000)
:ok = :ssl.send(socket, "hello")
{:ok, reply} = :ssl.recv(socket, 0, 5_000)
:ok = :ssl.close(socket)
```

- The stack does not resolve names. Thus, connect to an address.
  `:ssl.connect/4` with a host name returns `{:error, :einval}`.
  `server_name_indication` gives `:ssl` the name that it sends in the handshake.
  `:ssl` also compares the certificate with this name.
- If the certificate of the server comes from a private CA, give that CA in
  `cacertfile` instead of `cacerts`.
- In an application, add `:ssl` to `extra_applications`. Do not start `:ssl`
  manually.
- For IPv6, use `SmolNet.Inet6.Tcp` with `:inet6`.

The [`:ssl` guide](https://hexdocs.pm/smolnet/ssl.html) of SmolNet describes
servers, how to upgrade a connected socket, and how errors and timeouts occur.

### Inspect and stop an interface

`Wagyu.info/1` gives the counters and the peer state. `Wagyu.stop/1` stops
the interface. The module documentation for `Wagyu` and `Wagyu.Config`
describes these items:

- All the options.
- Names and handles.
- How to change the peers of a running interface.
- What occurs when a process fails, and how it restarts.
- The limits on queued work.

## License

MIT. See [LICENSE](https://github.com/ausimian/wagyu/blob/main/LICENSE).

To work on Wagyu itself, see
[MAINTAINING.md](https://github.com/ausimian/wagyu/blob/main/MAINTAINING.md).
