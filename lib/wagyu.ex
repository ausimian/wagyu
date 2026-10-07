defmodule Wagyu do
  @moduledoc """
  A user-mode WireGuard endpoint for `:gen_tcp` and `:gen_udp` sockets.

  Wagyu does not need a TUN device. Each interface runs its own userspace
  TCP/IP stack from SmolNet. The interface sends the IPv4 and IPv6 packets
  of that stack to its WireGuard peers through one UDP socket. Only the
  sockets that you open on the stack use the tunnel. The tunnel has no
  effect on the rest of the node.

  ## Starting an interface

  `start_link/1` validates the options, which `Wagyu.Config` describes.
  Then it starts a supervisor for the interface and links that supervisor
  to the caller. It returns `{:ok, pid}` with the PID of that supervisor,
  also when you give a `:name`. It also accepts a `Wagyu.Config` from
  `Wagyu.Config.new/1`.

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

  After the interface starts, you can change its peers with
  `replace_peers/2` (see [Changing peers](#module-changing-peers)). To
  change the private key, the listen address or the stack options, stop
  the interface and start it again.

  If the options are not valid, `start_link/1` returns the error from
  `Wagyu.Config.new/1`, for example
  `{:error, {:invalid_option, [:private_key], :missing}}`. If the UDP socket
  or the stack cannot start, `start_link/1` returns the usual supervisor
  error, `{:error, {:shutdown, {:failed_to_start_child, child, reason}}}`.
  For example, `reason` is `:eaddrinuse` if the listen port is already in
  use.

  To run an interface under your own supervisor, add `{Wagyu, options}` as a
  child:

      children = [
        {Wagyu, name: :wg0, private_key: local_private_key, peers: peers}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  `child_spec/1` validates the options. If the options are not valid, it
  raises `ArgumentError`. The message never includes option values.

  ## Names and handles

  `:name` registers the supervisor of the interface with a local atom,
  `{:global, term}` or `{:via, module, term}`. If a different process
  already has the name, the start fails with
  `{:error, {:already_started, pid}}`. The name becomes free when the
  interface stops or crashes.

  `stack/1`, `info/1`, `replace_peers/2`, `revoke_sessions/2` and `stop/1`
  accept the PID from `start_link/1` or the name. Each call looks up the name again. Thus the name always refers to
  the interface that has that name at the time of the call. A restarted
  interface has a new PID but keeps its name. For long-lived code, keep the
  name, not the PID.

  These functions return `{:error, :not_running}` if no interface runs
  under that PID or name. `stack/1`, `info/1`, `replace_peers/2` and
  `revoke_sessions/2` also return this error while the interface restarts.

    * `stack/1` returns `{:ok, stack}`. This is the SmolNet stack on which
      you open sockets, for example with
      `SmolNet.open(:inet, :stream, :tcp, stack: stack)`. Use the stack only
      for sockets. Do not call `SmolNet.ingress/2` on the stack, because
      the interface gives the stack its packets.
    * `info/1` returns `{:ok, info}` with counters, peer state and public
      keys. See `t:info/0`.
    * `stop/1` stops the interface, its UDP socket and its stack, and
      returns `:ok`. Do not use `stop/1` for an interface under your own
      supervisor. Its supervisor starts it again, because it is a permanent
      child. Use `Supervisor.terminate_child/2` instead.

  ## Changing peers

  `replace_peers/2` replaces the peer set of a running interface. The
  stack, the sockets and the sessions of unchanged peers stay. The new
  peer set has the same form as the `:peers` option, and gets the same
  checks. If the peer set is not valid, nothing changes.

      :ok = Wagyu.replace_peers(:wg0, peers)

  The interface applies a valid peer set in one step. After `:ok`, `info/1`
  shows the new peer set, and the interface routes all egress with the new
  AllowedIPs. The interface compares the old and the new configuration of
  each public key:

    * **Added.** The peer starts when traffic or a handshake first needs
      it. A peer with a persistent keepalive starts immediately.
    * **Removed.** The interface stops the process of the peer, and drops
      and counts the packets that wait for it. Its sessions stop, and the
      interface refuses its traffic and its handshakes. The interface also
      forgets the endpoint that it learned for the peer.
    * **AllowedIPs.** The routes change. Because prefixes can be nested,
      this can also change the sources that a different peer can send
      from.
    * **Endpoint.** A new endpoint replaces the current endpoint, also an
      endpoint that the peer learned from its traffic. A change to `nil`
      keeps the current endpoint.
    * **Persistent keepalive.** The peer uses the new interval. A change
      from 0 starts the peer. A change to 0 stops the keepalives.
    * **Preshared key.** New handshakes use the new key. The current
      sessions stay valid until they expire. To stop them, call
      `revoke_sessions/2` after `replace_peers/2` returns.

  A different public key is a different peer: the old peer is removed, and
  the new peer is added. A peer that stays keeps its sessions, its timers
  and its queued traffic. No change starts a new handshake.

  The interface admits a maximum of 512 inbound packets to a peer before
  the peer decrypts them. The peer checks these packets against the
  AllowedIPs that applied when the interface admitted them. Thus, for a
  short time after a change, the inbound check can use the old AllowedIPs.
  Outbound packets use the new routes immediately.

  The interface keeps the replay timestamps of a removed peer. Thus an
  attacker cannot replay a captured handshake initiation after you add the
  peer again. See `t:info/0`.

  ### Revoking sessions

  `revoke_sessions/2` discards the sessions of one peer and keeps its
  configuration. The interface stops the process of the peer, the same as
  for a removed peer. The routes, the learned endpoint and the replay
  timestamps of the peer stay. Thus egress to the peer always has a route.
  The next packet or handshake starts a new process, which completes a new
  handshake. A peer with a persistent keepalive starts again immediately.

  After `:ok`, no session from before the call carries traffic. A handshake
  from the remote side gets its peer from the interface, in sequence with
  the call:

    * A handshake that got its peer before the call goes to the old
      process, which the call stops.
    * A handshake that gets its peer after the call uses the current
      preshared key, and makes a new session with the new process. This
      also applies to an initiation that arrived before the call.

  Until the processes of the old peer exit, they can still send datagrams
  that the peer encrypted before the call.

  For example, to rotate a preshared key, change the key on the remote
  side, then do these steps:

      :ok = Wagyu.replace_peers(:wg0, peers_with_new_key)
      :ok = Wagyu.revoke_sessions(:wg0, remote_public_key)

  ## Failure and restart

  If the stack fails, or if the process that gives packets to the stack
  fails, the complete interface restarts with a new stack. This also
  applies to a stack that `SmolNet.stop_stack/1` stopped. The sockets on
  the old stack no longer work. Get the new stack with `stack/1` and open
  the sockets again.

  All other failures in the interface restart the protocol processes, but
  the stack and its sockets stay. The interface loses its sessions, and the
  peers complete new handshakes.

  The interface keeps the latest peer set from `replace_peers/2` in a
  separate process. Thus all of these failures keep the latest peer set,
  and you do not have to apply it again. The interface goes back to the
  peers of the start options in only two cases:

    * The process that keeps the peer set fails. It holds only data and
      does no I/O, so it is not expected to fail. It also stops if the
      internal registry of Wagyu fails. Then the complete interface
      restarts, with a new stack.
    * The supervisor of the interface restarts, for example because your
      supervisor restarted it.

  ## Timers

  Peers use the timers of WireGuard, the same as wireguard-go:

    * **Handshakes.** A packet for a peer that has no usable key waits while
      the peer starts a handshake. If an initiation gets no response, the
      peer sends it again every 5 seconds, plus up to 333 ms of jitter. The
      peer continues for 90 seconds after the last packet that had to wait.
      Then it drops the waiting packets. A peer never sends handshake
      messages less than 5 seconds apart.
    * **Rekeying.** The peer that started a handshake starts a new handshake
      when it sends with keys that are 120 seconds old. It also starts a new
      handshake when it receives with keys that are 165 seconds old. Either
      side rekeys after 2^60 messages. A peer never uses keys more than 180
      seconds after their handshake, or for more than 2^64 - 2^13 - 1
      messages. After that limit, the peer discards the keys.
    * **Keepalives.** If a peer received data but sent nothing for 10
      seconds, it sends an empty keepalive. If a peer sent data but received
      nothing for 15 seconds, it starts a new handshake. In all other
      conditions, an idle peer sends nothing. The exception is a peer with a
      persistent keepalive (see `Wagyu.Config`).
    * **Expiry.** The peer discards its keys 540 seconds after its last
      handshake, or after its last handshake attempt fails. Then its process
      exits, if the peer does not have a persistent keepalive. The next
      packet for the peer, or the next initiation from it, starts the peer
      again with its last endpoint.

  Changes to the system time have no effect on the timers, because the
  timers use the monotonic clock.

  ## Bounded work

  Each queue in an interface has a fixed size. Items that do not fit are
  dropped and counted in `info/1`:

    * The interface reads datagrams from the socket in batches of limited
      size.
    * Up to 8 handshake workers run, and up to 64 initiations wait for them.
    * Each peer queues up to 512 inbound packets or 1 MiB, and up to 128
      outbound packets or 256 KiB. It can also hold up to 128 packets or
      256 KiB that wait for a key.
    * Up to 2 accepted handshakes wait for the process of each peer.
    * The stack receives a maximum of 32 packets in each call, and only one
      call at a time.

  A flood of initiations cannot delay other traffic, because handshake
  cryptography runs in the workers, never in the process that reads the
  socket. As in wireguard-go and Linux, the interface accepts an initiation
  only if all of these conditions are true:

    * The initiation comes from a configured peer.
    * Its timestamp is later than all timestamps that the interface
      accepted from that peer.
    * It arrives at least 20 ms after the last initiation from that peer.

  The interface keeps the timestamps until the interface restarts. Thus it
  refuses a replayed initiation, even if the process of the peer restarted.
  It also keeps the timestamps of a peer that `replace_peers/2` removed, for
  a maximum of 1024 removed peers. If you add the peer again, the interface
  uses these timestamps.

  ### Under load

  The interface is under load while 8 or more initiations wait for a
  worker, or when a worker cannot start. This condition continues for one
  second after its cause stops. As in wireguard-go and Linux, the interface
  under load then checks MAC2. It does no handshake cryptography for an
  initiation or a response if its MAC2 does not use a cookie for its source
  address:

    * A message without such a MAC2 gets a cookie reply, encrypted with
      XChaCha20-Poly1305. The sender must send the message again with the
      cookie.
    * For each IPv4 address or IPv6 /64, the interface accepts a maximum of
      20 messages a second with such a MAC2, in bursts of 5.
    * Each cookie is bound to its source address and port. A cookie expires
      in 120 seconds or less, when the interface replaces its cookie secret.

  The interface never answers a handshake message with an invalid MAC1,
  under load or not. In the other direction, a peer can get a cookie reply
  from a remote party that is under load. Then, for the next 120 seconds,
  the peer adds MAC2 to the handshake messages that it sends to that party.

  ### Outbound flow control

  The stack can have a maximum of 128 packets or 256 KiB in transit to the
  peers. The stack gets credit back for each packet when the packet is
  sent, when it waits for a key, or when it is dropped. Because of this,
  outbound packets never overflow the queues of the interface. Data that
  the stack cannot send yet stays in its sockets. TCP keeps the data in the
  send buffer and slows down, as it does on a slow network. A UDP send
  waits until there is space.
  """

  alias Wagyu.Config

  @typedoc "The supervisor PID or registered name of an interface."
  @type interface :: pid() | atom() | {:global, term()} | {:via, module(), term()}

  @typedoc """
  What `info/1` returns.

    * `:public_key` - the interface's public key
    * `:listen` - the address and port of the UDP socket. If the configured
      port is `0`, this is the port that the OS selected.
    * `:peers` - for each configured peer, its public key, configured
      endpoint and AllowedIPs, and whether its process is `:running`. The
      list is sorted by public key. The process of a peer starts when
      outbound traffic or an accepted handshake first needs it.
    * `:counters` - the counters that follow. The link counters (`:egress`,
      `:egress_dropped`, `:ingress` and `:ingress_dropped`) stay for the
      life of the stack. The other counters start again from zero when the
      interface restarts.

  The counters are:

    * `:datagrams` - UDP datagrams received
    * `:invalid_datagrams` - datagrams that are not valid WireGuard messages
    * `:invalid_mac1` - handshake messages with a MAC1 that does not match
      the public key of this interface
    * `:initiations` - handshake initiations passed to a worker
    * `:initiations_dropped` - initiations dropped because the handshake
      queue was full
    * `:initiations_failed` - initiations that failed authentication, or
      that had a worker that failed
    * `:initiations_unknown_peer` - authenticated initiations from a key
      that is not a configured peer
    * `:initiations_replayed` - initiations with a timestamp that was not
      later than the last one accepted from the same peer. The interface
      keeps the timestamps until it restarts. It also keeps the timestamps
      of the last 1024 peers that `replace_peers/2` removed. When more
      peers are removed, it discards the timestamps of the peer that was
      removed first.
    * `:initiations_rate_limited` - initiations that arrived less than 20 ms
      after the last one accepted from the same peer
    * `:initiations_unavailable` - initiations for a peer process that
      could not start, or that already had 2 handshakes that waited
    * `:initiations_accepted` - initiations that the interface accepted and
      passed to the process of their peer
    * `:cookie_replies_sent` - cookie replies sent under load to initiations
      and responses with a valid MAC1 but no valid MAC2
    * `:handshakes_rate_limited` - initiations and responses with a valid
      MAC2 that the interface refused under load, because their source
      used all of its 20 a second, in bursts of 5
    * `:unknown_index` - responses, cookie replies and transport messages
      for a receiver index that no live peer holds, including indices
      retired in the last 180 seconds
    * `:inbound_routed` - responses, cookie replies and transport messages
      queued for the peer holding their receiver index
    * `:inbound_peer_dropped` - the same messages, dropped because the
      queue of the peer was full or the peer exited first
    * `:initiations_sent` - handshake initiations sent
    * `:initiations_no_endpoint` - handshakes that a peer needed but could
      not start, because it has no endpoint, either configured or learned
      from an initiation
    * `:responses_sent` - handshake responses sent
    * `:responses_accepted` - responses that completed a handshake this
      interface started
    * `:responses_invalid` - responses that reached their peer but did not
      match its current handshake or did not authenticate
    * `:cookie_replies_accepted` - cookie replies that reached their peer,
      answered the last handshake message that the peer sent, and
      decrypted. The peer then uses the cookie for MAC2.
    * `:cookie_replies_invalid` - cookie replies that reached their peer but
      did not decrypt, or that arrived after the peer accepted a cookie
      reply for the same message
    * `:keepalives_sent` - keepalives sent to confirm a handshake this
      interface started, to answer data after 10 seconds of silence, or as
      persistent keepalives
    * `:keys_confirmed` - handshakes that this interface responded to, for
      which the initiator confirmed the keys with its first transport
      message. This side sends with these keys only after that
      confirmation.
    * `:transport_invalid` - transport messages that reached their peer but
      did not authenticate with any of its keys
    * `:transport_replayed` - transport messages refused before decryption,
      because their counter was a duplicate or too old for the replay window
    * `:transport_expired` - transport messages refused because their key
      was 180 seconds old or more
    * `:transport_sent` - packets encrypted and sent to peers
    * `:transport_received` - packets that authenticated, came from the
      AllowedIPs of their peer, and went into the queue for the stack.
      `:ingress_dropped` counts the packets that the link could not queue.
    * `:keepalives_received` - keepalives received
    * `:transport_malformed` - authenticated packets that are not valid IP,
      including packets with an IP length that is more than the data
    * `:transport_source_denied` - authenticated packets from a source
      outside the AllowedIPs of their peer
    * `:staged_dropped` - packets that waited for a key and were dropped,
      because the peer already had 128 packets or 256 KiB that waited, or
      because its handshake attempt failed. For the total outbound loss of
      a peer, add `:egress_peer_dropped`.
    * `:handshakes_abandoned` - handshake attempts that got no response
      after 90 seconds of retries
    * `:send_errors` - datagrams a peer failed to send
    * `:egress` - packets the stack sent
    * `:egress_dropped` - packets from the stack, dropped because the
      interface was in a restart or had exited
    * `:egress_unroutable` - packets from the stack with a malformed IP
      header or no matching AllowedIPs prefix
    * `:egress_routed` - packets queued for their peer
    * `:egress_peer_dropped` - packets dropped on the way to their peer,
      because its process could not start, or exited before it took them or
      while they waited for a key. `:staged_dropped` counts the packets that
      the peer had no space to hold.
    * `:ingress` - packets the stack accepted
    * `:ingress_dropped` - packets for the stack, dropped because the queue
      of the link was full or the stack refused them
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

  The id of the spec is `{Wagyu, name}` for a named interface and `Wagyu`
  for an unnamed interface. To run more than one unnamed interface under
  one supervisor, change the id with `Supervisor.child_spec/2`.

  Raises `ArgumentError` if `options` are not valid. The message includes
  the error from `Wagyu.Config.new/1`, which never contains option values.
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

  `Wagyu.Config` describes the `options`. The function also accepts a
  `Wagyu.Config` from `Wagyu.Config.new/1`. It returns `{:ok, pid}` with
  the supervisor of the interface. If the options are not valid, it returns
  the error from `Wagyu.Config.new/1`.
  """
  @spec start_link(keyword() | Config.t()) :: Supervisor.on_start() | {:error, Config.error()}
  def start_link(%Config{} = config), do: Wagyu.Interface.Supervisor.start_link(config)

  def start_link(options) do
    with {:ok, config} <- Config.new(options), do: start_link(config)
  end

  @doc "Returns the SmolNet stack reference for the sockets of the interface."
  @spec stack(interface()) :: {:ok, SmolNet.Stack.Ref.t()} | {:error, :not_running}
  def stack(interface) do
    with {:ok, root} <- root(interface),
         {:ok, _link, %{stack: stack}} <- Wagyu.Registry.lookup(root, :link) do
      {:ok, stack}
    else
      _not_running -> {:error, :not_running}
    end
  end

  @doc "Returns the counters, peer state and public keys of the interface. See `t:info/0`."
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

  @doc """
  Replaces the peers of a running interface.

  `peers` has the same form as the `:peers` option of `Wagyu.Config`, and
  gets the same checks and limits. The interface applies a valid peer set in
  one step. See [Changing peers](#module-changing-peers).

  Returns one of these values:

    * `:ok`
    * `{:error, {:invalid_option, path, reason}}` - an invalid option, with
      the same path and reason as from `Wagyu.Config.new/1`. `path` starts
      with `[:peers, index]`. Nothing changes.

  The caller does the checks that do not need the interface first. The
  interface then does the checks of the endpoint families and of the public
  keys. Thus, if more than one option is not valid, the error can be for a
  different option than the first error of `Wagyu.Config.new/1`.
    * `{:error, :not_running}` - no interface runs under that PID or name.
      This error also occurs if the interface restarts during the call. In
      that case, the new peer set can be in force or not. Call the function
      again.
  """
  @spec replace_peers(interface(), [map()]) :: :ok | {:error, Config.error() | :not_running}
  def replace_peers(interface, peers) do
    with {:ok, peers} <- Config.build_peers(peers),
         {:ok, pid} <- interface_process(interface) do
      Wagyu.Interface.replace_peers(pid, peers)
    end
  end

  @doc """
  Discards the sessions of the peer with `public_key`, and keeps its
  configuration. The next packet or handshake makes a new session. See
  [Revoking sessions](#module-revoking-sessions).

  Returns one of these values:

    * `:ok` - also if the peer had no sessions
    * `{:error, :unknown_peer}` - `public_key` is not in the peer set
    * `{:error, :not_running}` - no interface runs under that PID or name
  """
  @spec revoke_sessions(interface(), <<_::256>>) :: :ok | {:error, :unknown_peer | :not_running}
  def revoke_sessions(interface, public_key) do
    with {:ok, pid} <- interface_process(interface), do: Wagyu.Interface.revoke_sessions(pid, public_key)
  end

  @doc "Stops the interface, its UDP socket and its SmolNet stack."
  @spec stop(interface()) :: :ok | {:error, :not_running}
  def stop(interface) do
    with {:ok, root} <- root(interface), do: Supervisor.stop(root)
  catch
    # The interface stopped for a different reason between the lookup and
    # the call.
    :exit, {:noproc, _call} -> {:error, :not_running}
  end

  defp config!(%Config{} = config), do: config

  defp config!(options) do
    case Config.new(options) do
      {:ok, config} -> config
      {:error, reason} -> raise ArgumentError, "invalid Wagyu options: " <> inspect(reason)
    end
  end

  defp interface_process(interface) do
    with {:ok, root} <- root(interface),
         {:ok, pid, _value} <- Wagyu.Registry.lookup(root, :interface) do
      {:ok, pid}
    else
      _not_running -> {:error, :not_running}
    end
  end

  # If a PID or name does not belong to a live interface supervisor on
  # this node, the interface is not running. The check does not use the
  # registry. As a result, the check is also correct while the registry
  # restarts.
  defp root(interface) do
    with pid when is_pid(pid) and node(pid) == node() <- GenServer.whereis(interface),
         {:supervisor, Wagyu.Interface.Supervisor, _args} <- :proc_lib.initial_call(pid) do
      {:ok, pid}
    else
      _not_running -> {:error, :not_running}
    end
  end
end
