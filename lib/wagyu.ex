defmodule Wagyu do
  @moduledoc """
  A user-mode WireGuard endpoint for SmolNet application sockets.

  A Wagyu interface carries complete IPv4 and IPv6 packets between one SmolNet
  network stack and its WireGuard peers over a single UDP socket. There is no
  host TUN device: only sockets opened on the interface's stack use the
  tunnel.

  > #### Status {: .warning}
  >
  > An interface completes WireGuard handshakes with its configured peers,
  > both ways, and carries the TCP and UDP traffic of sockets opened on its
  > stack. A packet sent to a peer with no usable key waits while the peer
  > starts a handshake. Handshakes that fail are not retried on a timer yet,
  > and keys are not replaced before they expire: 180 seconds after a
  > handshake, a key is no longer used, and the next packet starts a new
  > handshake. `info/1` counts all of it.

  ## Starting an interface

  `Wagyu.start_link(options)` validates `options`, described in
  `Wagyu.Config`, and starts the interface's own supervisor linked to the
  caller. On success it returns `{:ok, pid}`, where `pid` is that
  per-interface supervisor, whether or not a `:name` is given. Invalid options
  fail startup with the error `Wagyu.Config.new/1` returns, such as
  `{:error, :unsupported_preshared_key}`. `start_link/1` also accepts a
  configuration that `Wagyu.Config.new/1` has already validated.

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

  If the interface cannot open its UDP socket or start its stack, startup
  fails with the supervisor's usual
  `{:error, {:shutdown, {:failed_to_start_child, child, reason}}}`, for
  example with `reason` `:eaddrinuse` when the listen port is taken.

  To run an interface in your own supervision tree instead, list
  `{Wagyu, options}` as a child. `Wagyu.child_spec(options)` returns a spec
  that starts the same per-interface supervisor through `start_link`:

      children = [
        {Wagyu, name: :wg0, private_key: local_private_key, peers: peers}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  `child_spec/1` validates the options when it builds the spec and raises
  `ArgumentError` if they are invalid. Its message names the error that
  `Wagyu.Config.new/1` returns, and like that error it never includes option
  values. The spec's start argument is the validated `Wagyu.Config`, not the
  options, so the private key is not stored in the spec in raw form.

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
  name, so long-lived callers should hold the name. Each returns
  `{:error, :not_running}` when no interface is running under that PID or
  name, and `stack/1` and `info/1` also return it while the interface is
  restarting.

    * `Wagyu.stack(interface)` returns `{:ok, stack}`, the SmolNet stack
      reference to open sockets on, for example with
      `SmolNet.open(:inet, :stream, :tcp, stack: stack)`. The interface is
      the stack's only packet feeder; use the reference for socket calls,
      not `SmolNet.ingress/2`.
    * `Wagyu.info(interface)` returns `{:ok, info}` with counters, peer state
      and public keys. It never includes private keys, preshared keys or
      session keys. See `t:info/0`.
    * `Wagyu.stop(interface)` stops the interface, its UDP socket and its
      stack, and returns `:ok`. An interface under your own supervisor is a
      permanent child by default and is restarted; remove it with
      `Supervisor.terminate_child/2` instead.

  ## Failure and restart

  The interface's supervisor owns the SmolNet stack and the processes that
  run the protocol. If the stack, or the process that feeds it packets, fails,
  the whole interface restarts with a new stack and every socket opened on the
  old one becomes invalid: fetch the new stack with `Wagyu.stack(interface)`
  and reopen them. This includes a stack stopped with `SmolNet.stop_stack/1`.
  A failure elsewhere in the interface restarts the protocol processes and
  loses their sessions, but keeps the stack and its open sockets; peers then
  complete fresh handshakes.

  ## Bounded work

  Every queue between the interface's own processes has a fixed bound, and
  anything beyond it is dropped and counted rather than queued: datagrams
  are read from the socket a bounded batch at a time, at most 8 handshake
  workers run with at most 64 initiations waiting, each peer queues at most
  128 packets or 256 KiB in each direction, and as many again waiting for a
  key to send them with, and packets the stack sends
  beyond what the interface has queued are dropped. At most 32 packets reach
  the stack in one ingress call, one call at a time.

  Handshake cryptography for initiations that arrive runs only in the
  workers, never in the process that reads the socket, so a flood of
  initiations cannot hold up other datagrams. An initiation is accepted
  only from a configured peer, only with a timestamp later than any
  accepted from that peer before, and at most once every 20 ms per peer, as
  in wireguard-go and Linux. The interface keeps these timestamps until it
  restarts, so a replay is refused even after the peer's own process
  restarts. At most 2 accepted handshakes wait for each peer's process,
  apart from its other queues; beyond that, new ones are refused until it
  catches up. A peer starts a handshake at most once every 5 seconds, and
  not within 5 seconds of responding to one, as wireguard-go does.

  The one exception is the stack's own output. SmolNet sends each outbound
  batch to the interface without backpressure, so nothing bounds those
  messages before they arrive; the interface drains them promptly and drops
  whatever its queue cannot take. Only the application's own sockets
  produce that output, at most 32 packets per step of the stack, so it
  keeps pace with the stack rather than with remote traffic.

  ## Keys and logs

  The private key and preshared keys stay out of logs. Supervisors hold the
  validated `Wagyu.Config` rather than the raw options, and processes that
  hold keys replace them with `:redacted` in their status and crash reports.
  Supervisor reports format the configuration through its `Inspect`
  implementation, which omits keys; see `Wagyu.Config` for what bypasses it,
  such as a handler configured with Erlang's own formatter.
  """

  alias Wagyu.Config

  @typedoc "An interface's supervisor PID or registered name."
  @type interface :: pid() | atom() | {:global, term()} | {:via, module(), term()}

  @typedoc """
  What `info/1` returns.

    * `:public_key` - the interface's public key
    * `:listen` - the UDP socket's local address and bound port, which
      differs from the configured port when that is `0`
    * `:peers` - each configured peer's public key, configured endpoint and
      AllowedIPs, sorted by public key, and whether its process is
      `:running`. Peer processes start when outbound traffic or an accepted
      handshake initiation first needs them.
    * `:counters` - packet counters. The link's (`:egress`, `:egress_dropped`,
      `:ingress`, `:ingress_dropped`) last as long as the stack; the others
      reset when the interface restarts.

  The counters are:

    * `:datagrams` - UDP datagrams received
    * `:invalid_datagrams` - datagrams that are not well-formed WireGuard
      messages
    * `:invalid_mac1` - handshake messages whose MAC1 does not match this
      interface's public key
    * `:initiations` - handshake initiations handed to a worker
    * `:initiations_dropped` - initiations refused because the handshake
      queue was full
    * `:initiations_failed` - initiations that failed authentication, or
      whose worker failed
    * `:initiations_unknown_peer` - authenticated initiations from a key
      that is not a configured peer
    * `:initiations_replayed` - initiations whose timestamp was not later
      than the last one accepted from their peer
    * `:initiations_rate_limited` - initiations less than 20 ms after the
      last one accepted from their peer
    * `:initiations_unavailable` - initiations whose peer process could not
      be started or already had as many handshakes waiting as it may
    * `:initiations_accepted` - initiations authorized and passed to their
      peer's process
    * `:unknown_index` - responses, cookie replies and transport messages
      for a receiver index with no live peer, including one retired in the
      last 180 seconds
    * `:inbound_routed` - responses, cookie replies and transport messages
      queued for the peer holding their receiver index
    * `:inbound_peer_dropped` - those dropped because the peer's queue was
      full or it exited before taking them
    * `:initiations_sent` - handshake initiations sent to peers
    * `:initiations_no_endpoint` - handshakes that a peer needed but could
      not start, because it has no endpoint: none configured, and none
      learned from an initiation it accepted
    * `:responses_sent` - handshake responses sent to accepted initiations
    * `:responses_accepted` - responses that authenticated and completed a
      handshake this interface initiated
    * `:responses_invalid` - responses that reached their peer but were not
      for its handshake in progress or did not authenticate
    * `:keepalives_sent` - empty transport messages sent to confirm a
      handshake this interface initiated
    * `:keys_confirmed` - handshakes this interface responded to whose keys
      the initiator confirmed with its first transport message, after which
      the responder sends with them
    * `:transport_invalid` - transport messages that reached their peer but
      did not authenticate under any of its keys
    * `:transport_replayed` - transport messages refused, before
      decryption, because their counter was already accepted or is too old
      for the key's replay window
    * `:transport_expired` - transport messages refused because their key
      is 180 seconds old or more
    * `:transport_sent` - packets encrypted and sent to peers
    * `:transport_received` - packets that authenticated, came from an
      address in their peer's AllowedIPs and were queued for the stack; the
      link counts those it could not queue in `:ingress_dropped`
    * `:keepalives_received` - authenticated empty transport messages
    * `:transport_malformed` - authenticated packets that are not valid IP,
      including those whose IP length exceeds the decrypted data
    * `:transport_source_denied` - authenticated packets whose source
      address is not in their peer's AllowedIPs
    * `:staged_dropped` - packets dropped because their peer had no usable
      key and already held as many packets waiting for one as it may
    * `:send_errors` - datagrams that a peer failed to send
    * `:egress` - packets the stack sent
    * `:egress_dropped` - packets the stack sent that were dropped because
      the interface's queue was full, it was restarting, or it exited before
      taking them
    * `:egress_unroutable` - packets with a malformed IP header or no
      matching AllowedIPs prefix
    * `:egress_routed` - packets queued for their peer
    * `:egress_peer_dropped` - packets dropped because the peer's queue was
      full, it could not start, or it exited before taking them or while
      they waited for a key
    * `:ingress` - packets the stack accepted
    * `:ingress_dropped` - packets bound for the stack that were dropped,
      because the link's queue was full or the stack refused them
  """
  @type info :: %{
          public_key: <<_::256>>,
          listen: %{address: :inet.ip_address(), port: :inet.port_number()},
          peers: [
            %{
              public_key: <<_::256>>,
              endpoint: %{address: :inet.ip_address(), port: :inet.port_number()} | nil,
              allowed_ips: [{:inet.ip_address(), non_neg_integer()}],
              running: boolean()
            }
          ],
          counters: %{atom() => non_neg_integer()}
        }

  @doc """
  Returns a child spec that starts an interface with `options`.

  The spec's id is `{Wagyu, name}` for a named interface and `Wagyu`
  otherwise; override it with `Supervisor.child_spec/2` to run several
  unnamed interfaces under one supervisor.

  Raises `ArgumentError` if `options` are invalid. The message includes the
  error from `Wagyu.Config.new/1`, which never contains option values.
  """
  @spec child_spec(keyword() | Config.t()) :: Supervisor.child_spec()
  def child_spec(options) do
    config = config!(options)

    %{
      id: if(config.name, do: {__MODULE__, config.name}, else: __MODULE__),
      start: {__MODULE__, :start_link, [config]},
      type: :supervisor
    }
  end

  @doc """
  Starts an interface linked to the caller.

  `options` are described in `Wagyu.Config`; a `Wagyu.Config` from
  `Wagyu.Config.new/1` is accepted too. Returns `{:ok, pid}` with the
  interface's supervisor. Invalid options return the error from
  `Wagyu.Config.new/1`.
  """
  @spec start_link(keyword() | Config.t()) :: Supervisor.on_start() | {:error, Config.error()}
  def start_link(%Config{} = config), do: Wagyu.Interface.Supervisor.start_link(config)

  def start_link(options) do
    with {:ok, config} <- Config.new(options), do: start_link(config)
  end

  @doc "Returns the SmolNet stack reference for the interface's sockets."
  @spec stack(interface()) :: {:ok, SmolNet.Stack.Ref.t()} | {:error, :not_running}
  def stack(interface) do
    with {:ok, root} <- root(interface),
         {:ok, _link, %{stack: stack}} <- Wagyu.Registry.lookup(root, :link) do
      {:ok, stack}
    else
      _not_running -> {:error, :not_running}
    end
  end

  @doc "Returns the interface's counters, peer state and public keys. See `t:info/0`."
  @spec info(interface()) :: {:ok, info()} | {:error, :not_running}
  def info(interface) do
    with {:ok, root} <- root(interface),
         {:ok, pid, _value} <- Wagyu.Registry.lookup(root, :interface),
         {:ok, info} <- Wagyu.Interface.info(pid),
         {:ok, link} <- Wagyu.Link.counters(root) do
      {:ok, %{info | counters: Map.merge(info.counters, link)}}
    else
      _not_running -> {:error, :not_running}
    end
  end

  @doc "Stops the interface, its UDP socket and its SmolNet stack."
  @spec stop(interface()) :: :ok | {:error, :not_running}
  def stop(interface) do
    with {:ok, root} <- root(interface), do: Supervisor.stop(root)
  catch
    # It stopped on its own between the lookup and the call.
    :exit, {:noproc, _call} -> {:error, :not_running}
  end

  defp config!(%Config{} = config), do: config

  defp config!(options) do
    case Config.new(options) do
      {:ok, config} -> config
      {:error, reason} -> raise ArgumentError, "invalid Wagyu options: " <> inspect(reason)
    end
  end

  # A PID or name that belongs to anything other than a live interface
  # supervisor on this node is not running. The check does not use the
  # registry, so it holds while the registry restarts.
  defp root(interface) do
    with pid when is_pid(pid) and node(pid) == node() <- GenServer.whereis(interface),
         {:supervisor, Wagyu.Interface.Supervisor, _args} <- :proc_lib.initial_call(pid) do
      {:ok, pid}
    else
      _not_running -> {:error, :not_running}
    end
  end
end
