defmodule Wagyu do
  @moduledoc """
  A user-mode WireGuard endpoint for SmolNet application sockets.

  A Wagyu interface carries complete IPv4 and IPv6 packets between one SmolNet
  network stack and its WireGuard peers over a single UDP socket. There is no
  host TUN device: only sockets opened on the interface's stack use the
  tunnel.

  > #### Status {: .warning}
  >
  > This release provides configuration validation, `Wagyu.Config.new/1`, and
  > the WireGuard wire-format building blocks. The functions described below
  > are the interface's contract; they are not implemented yet.

  ## Starting an interface

  `Wagyu.start_link(options)` validates `options`, described in
  `Wagyu.Config`, and starts the interface's own supervisor linked to the
  caller. On success it returns `{:ok, pid}`, where `pid` is that
  per-interface supervisor, whether or not a `:name` is given. Invalid options
  fail startup with the error `Wagyu.Config.new/1` returns, such as
  `{:error, :unsupported_preshared_key}`.

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

  To run an interface in your own supervision tree instead, list
  `{Wagyu, options}` as a child. `Wagyu.child_spec(options)` returns a spec
  that starts the same per-interface supervisor through `start_link`:

      children = [
        {Wagyu, name: :wg0, private_key: local_private_key, peers: peers}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  ## Names and handles

  The optional `:name` registers the per-interface supervisor under a standard
  OTP name: an atom for local registration, `{:global, term}`, or
  `{:via, module, term}`. A name that is already registered fails startup with
  the usual `{:error, {:already_started, pid}}`. The name is released when the
  interface stops or crashes.

  `Wagyu.stack(interface)`, `Wagyu.info(interface)` and
  `Wagyu.stop(interface)` accept either the PID that `start_link` returned or
  the registered name. A name is resolved when each call is made, as
  `GenServer.whereis/1` does, so it always refers to whichever interface
  currently holds it; a PID refers to one started interface. When a
  supervisor restarts an interface, the new one has a new PID but the same
  name, so long-lived callers should hold the name.

    * `Wagyu.stack(interface)` returns `{:ok, stack}`, the SmolNet stack
      reference to open sockets on, for example with
      `SmolNet.open(:inet, :stream, :tcp, stack: stack)`.
    * `Wagyu.info(interface)` returns `{:ok, info}` with counters, peer state
      and public keys. It never includes private keys, preshared keys or
      session keys.
    * `Wagyu.stop(interface)` stops the interface, its UDP socket and its
      stack, and returns `:ok`.

  ## Failure and restart

  The interface's supervisor owns the SmolNet stack and the processes that
  run the protocol. If the stack, or the process that feeds it packets, fails,
  the whole interface restarts with a new stack and every socket opened on the
  old one becomes invalid: fetch the new stack with `Wagyu.stack(interface)`
  and reopen them. A failure elsewhere in the interface restarts the protocol
  processes and loses their sessions, but keeps the stack and its open
  sockets; peers then complete fresh handshakes.
  """
end
