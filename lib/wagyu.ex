defmodule Wagyu do
  @moduledoc """
  A user-mode WireGuard endpoint for `:gen_tcp` and `:gen_udp` sockets.

  Wagyu needs no TUN device. Each interface runs its own userspace TCP/IP
  stack, provided by SmolNet, and sends that stack's IPv4 and IPv6 packets to
  its WireGuard peers over a single UDP socket. Only sockets opened on the
  stack use the tunnel; the rest of the node is unaffected.

  ## Starting an interface

  `start_link/1` validates the options, described in `Wagyu.Config`, and
  starts a supervisor for the interface, linked to the caller. It returns
  `{:ok, pid}` with that supervisor's PID, whether or not you give a
  `:name`. It also accepts a `Wagyu.Config` from `Wagyu.Config.new/1`.

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

  The configuration is fixed once the interface starts. To change it, stop
  the interface and start it again.

  Invalid options return the error from `Wagyu.Config.new/1`, such as
  `{:error, {:invalid_option, [:private_key], :missing}}`. If the UDP socket
  or the stack can't start, `start_link/1` returns the usual supervisor
  error, `{:error, {:shutdown, {:failed_to_start_child, child, reason}}}`;
  for example, `reason` is `:eaddrinuse` if the listen port is taken.

  To run an interface under your own supervisor, add `{Wagyu, options}` as a
  child:

      children = [
        {Wagyu, name: :wg0, private_key: local_private_key, peers: peers}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  `child_spec/1` validates the options and raises `ArgumentError` if they
  are invalid. The message never includes option values. The spec carries
  the validated `Wagyu.Config` rather than the options, so supervisor
  reports don't show the private key.

  ## Names and handles

  `:name` registers the interface's supervisor as a local atom,
  `{:global, term}` or `{:via, module, term}`. If the name is taken, startup
  fails with `{:error, {:already_started, pid}}`. The name is released when
  the interface stops or crashes.

  `stack/1`, `info/1` and `stop/1` take either the PID from `start_link/1`
  or the name. A name is looked up on every call, so it always refers to the
  interface currently registered under it. A restarted interface has a new
  PID but keeps its name, so long-lived code should hold on to the name. All
  three return `{:error, :not_running}` if no interface is running under
  that PID or name; `stack/1` and `info/1` also return it while the
  interface restarts.

    * `stack/1` returns `{:ok, stack}`, the SmolNet stack to open sockets
      on, for example with `SmolNet.open(:inet, :stream, :tcp, stack: stack)`.
      Use it only for sockets: the interface feeds the stack its packets, so
      don't call `SmolNet.ingress/2` on it.
    * `info/1` returns `{:ok, info}` with counters, peer state and public
      keys, and never private, preshared or session keys. See `t:info/0`.
    * `stop/1` stops the interface, its UDP socket and its stack, and
      returns `:ok`. An interface under your own supervisor is a permanent
      child, so that supervisor restarts it; use
      `Supervisor.terminate_child/2` instead.

  ## Failure and restart

  If the stack fails, or the process that feeds it packets does, the whole
  interface restarts with a new stack. That includes a stack stopped with
  `SmolNet.stop_stack/1`. Sockets on the old stack stop working: get the new
  stack with `stack/1` and reopen them.

  Any other failure inside the interface restarts the protocol processes but
  keeps the stack and its sockets. Sessions are lost, and peers complete new
  handshakes.

  ## Timers

  Peers follow WireGuard's timers, the same as wireguard-go:

    * **Handshakes.** A packet for a peer with no usable key waits while the
      peer starts a handshake. An unanswered initiation is resent every 5
      seconds, plus up to 333 ms of jitter, for 90 seconds after the last
      packet that had to wait; then the waiting packets are dropped. A peer
      never sends handshake messages less than 5 seconds apart.
    * **Rekeying.** The peer that started a handshake starts a new one when
      it sends under keys 120 seconds old, or receives under keys 165
      seconds old. Either side rekeys after 2^60 messages. Keys are never
      used more than 180 seconds after their handshake or for more than
      2^64 - 2^13 - 1 messages; they are then discarded.
    * **Keepalives.** A peer that has received data but sent nothing for 10
      seconds sends an empty keepalive. One that has sent data but received
      nothing for 15 seconds starts a new handshake. Otherwise an idle peer
      sends nothing, unless it has a persistent keepalive (see
      `Wagyu.Config`).
    * **Expiry.** 540 seconds after a peer's last handshake, or after its
      last handshake attempt gives up, the peer discards its keys, and its
      process exits unless it has a persistent keepalive. The next packet
      for the peer, or initiation from it, starts it again with its last
      endpoint.

  Timers use the monotonic clock, so changing the system time doesn't
  affect them.

  ## Bounded work

  Every queue inside an interface has a fixed size. Anything that doesn't
  fit is dropped and counted in `info/1`:

    * Datagrams are read from the socket in batches of bounded size.
    * Up to 8 handshake workers run, with up to 64 initiations waiting.
    * Each peer queues up to 128 packets or 256 KiB in each direction, plus
      as many again waiting for a key.
    * Up to 2 accepted handshakes wait for each peer's process.
    * The stack receives at most 32 packets per call, one call at a time.

  Handshake cryptography runs in the workers, never in the process reading
  the socket, so a flood of initiations can't hold up other traffic. As in
  wireguard-go and Linux, an initiation is accepted only if it comes from a
  configured peer, its timestamp is later than any accepted from that peer,
  and it arrives at least 20 ms after the peer's last one. The interface
  remembers timestamps until it restarts, so a replayed initiation is
  refused even if the peer's process has restarted.

  ### Under load

  The interface is under load while 8 or more initiations are waiting for a
  worker, or a worker can't start, and for one second after. As in
  wireguard-go and Linux, it then does no handshake cryptography for an
  initiation or response unless its MAC2 was made with a cookie for its
  source address:

    * A message without one gets a cookie reply, encrypted with
      XChaCha20-Poly1305, and the sender must retry with the cookie.
    * Messages with one are limited to 20 a second, in bursts of 5, per
      IPv4 address or IPv6 /64.
    * Cookies are bound to the source address and port, and expire within
      120 seconds, when the interface replaces its cookie secret.

  A handshake message with an invalid MAC1 is never answered, under load or
  not. In the other direction, when a peer gets a cookie reply from a remote
  party under load, it adds MAC2 to the handshake messages it sends there
  for the next 120 seconds.

  ### Outbound flow control

  The stack can have at most 128 packets or 256 KiB in flight to the peers,
  and gets credit back as each packet is sent, set aside to wait for a key,
  or dropped. Outbound packets therefore never overflow the interface's
  queues. Data the stack can't send yet stays in its sockets: TCP holds it
  in the send buffer and slows down as it would on a slow network, and a UDP
  send waits until there's room.

  ## Keys and logs

  The private key and preshared keys are kept out of logs. Supervisors hold
  the validated `Wagyu.Config`, whose `Inspect` implementation hides the
  keys, and processes that hold keys show them as `:redacted` in their
  status and crash reports. Some log formatting bypasses `Inspect`, such as
  a handler that uses Erlang's own formatter; see `Wagyu.Config`.
  """

  alias Wagyu.Config

  @typedoc "An interface's supervisor PID or registered name."
  @type interface :: pid() | atom() | {:global, term()} | {:via, module(), term()}

  @typedoc """
  What `info/1` returns.

    * `:public_key` - the interface's public key
    * `:listen` - the UDP socket's address and port. If the configured port
      is `0`, this is the port the OS chose.
    * `:peers` - each configured peer's public key, configured endpoint and
      AllowedIPs, sorted by public key, and whether its process is
      `:running`. A peer's process starts when outbound traffic or an
      accepted handshake first needs it.
    * `:counters` - the counters below. The link's counters (`:egress`,
      `:egress_dropped`, `:ingress` and `:ingress_dropped`) last as long as
      the stack; the rest reset when the interface restarts.

  The counters are:

    * `:datagrams` - UDP datagrams received
    * `:invalid_datagrams` - datagrams that aren't valid WireGuard messages
    * `:invalid_mac1` - handshake messages with a MAC1 that doesn't match
      this interface's public key
    * `:initiations` - handshake initiations passed to a worker
    * `:initiations_dropped` - initiations dropped because the handshake
      queue was full
    * `:initiations_failed` - initiations that failed authentication, or
      whose worker failed
    * `:initiations_unknown_peer` - authenticated initiations from a key
      that isn't a configured peer
    * `:initiations_replayed` - initiations whose timestamp wasn't later
      than the last one accepted from the same peer
    * `:initiations_rate_limited` - initiations that arrived less than 20 ms
      after the last one accepted from the same peer
    * `:initiations_unavailable` - initiations whose peer process couldn't
      start or already had 2 handshakes waiting
    * `:initiations_accepted` - initiations accepted and passed to their
      peer's process
    * `:cookie_replies_sent` - cookie replies sent under load to initiations
      and responses with a valid MAC1 but no valid MAC2
    * `:handshakes_rate_limited` - initiations and responses with a valid
      MAC2 refused under load because their source had used up its 20 a
      second, in bursts of 5
    * `:unknown_index` - responses, cookie replies and transport messages
      for a receiver index that no live peer holds, including indices
      retired in the last 180 seconds
    * `:inbound_routed` - responses, cookie replies and transport messages
      queued for the peer holding their receiver index
    * `:inbound_peer_dropped` - the same messages, dropped because the
      peer's queue was full or the peer exited first
    * `:initiations_sent` - handshake initiations sent
    * `:initiations_no_endpoint` - handshakes a peer needed but couldn't
      start because it has no endpoint, either configured or learned from
      an initiation
    * `:responses_sent` - handshake responses sent
    * `:responses_accepted` - responses that completed a handshake this
      interface started
    * `:responses_invalid` - responses that reached their peer but didn't
      match its current handshake or didn't authenticate
    * `:cookie_replies_accepted` - cookie replies that answered the last
      handshake message sent to their peer and decrypted; the peer then uses
      the cookie for MAC2
    * `:cookie_replies_invalid` - cookie replies that reached their peer but
      didn't decrypt, or arrived after one for the same message had been
      accepted
    * `:keepalives_sent` - keepalives sent to confirm a handshake this
      interface started, to answer data after 10 seconds of silence, or as
      persistent keepalives
    * `:keys_confirmed` - handshakes this interface responded to whose keys
      the initiator confirmed with its first transport message; only then
      does this side send with them
    * `:transport_invalid` - transport messages that reached their peer but
      didn't authenticate under any of its keys
    * `:transport_replayed` - transport messages refused before decryption
      because their counter had already been seen or was too old for the
      replay window
    * `:transport_expired` - transport messages refused because their key
      was 180 seconds old or more
    * `:transport_sent` - packets encrypted and sent to peers
    * `:transport_received` - packets that authenticated, came from their
      peer's AllowedIPs and were queued for the stack. Packets the link
      couldn't queue are counted in `:ingress_dropped`.
    * `:keepalives_received` - keepalives received
    * `:transport_malformed` - authenticated packets that aren't valid IP,
      including those whose IP length exceeds the data
    * `:transport_source_denied` - authenticated packets from a source
      outside their peer's AllowedIPs
    * `:staged_dropped` - packets dropped while waiting for a key, because
      the peer already had 128 packets or 256 KiB waiting, or its handshake
      attempt gave up. Add `:egress_peer_dropped` for a peer's total
      outbound loss.
    * `:handshakes_abandoned` - handshake attempts that got no response in
      90 seconds of retries
    * `:send_errors` - datagrams a peer failed to send
    * `:egress` - packets the stack sent
    * `:egress_dropped` - packets from the stack dropped because the
      interface was restarting or had exited
    * `:egress_unroutable` - packets from the stack with a malformed IP
      header or no matching AllowedIPs prefix
    * `:egress_routed` - packets queued for their peer
    * `:egress_peer_dropped` - packets dropped on the way to their peer,
      because its process couldn't start, or exited before taking them or
      while they waited for a key. Packets the peer had no room to hold are
      counted in `:staged_dropped` instead.
    * `:ingress` - packets the stack accepted
    * `:ingress_dropped` - packets for the stack dropped because the link's
      queue was full or the stack refused them
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
