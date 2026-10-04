defmodule Wagyu.Interface do
  @moduledoc false

  # The owner of the UDP socket, and a shallow demultiplexer.
  #
  # The interface owns these items:
  #
  #   * the real UDP socket
  #   * the configuration and its AllowedIPs routes
  #   * the table from configured public keys to running peer processes
  #   * the local receiver-index table
  #   * the greatest initiation timestamp accepted from each peer
  #
  # For each datagram, the interface does only a fixed quantity of work:
  # decode, MAC1 and MAC2 checks, a cookie reply, admission and an index
  # lookup. It never runs Noise.
  #
  # The socket is in bounded active mode. It delivers `@active` datagrams,
  # and then it waits until the interface arms it again. Thus datagrams
  # never collect in the mailbox faster than the interface processes them.
  # Valid initiations are admitted to a bounded pool of handshake workers
  # (`Wagyu.HandshakeQueue`). The workers run Noise, and then claim their
  # peer here with `claim_peer/3`.
  #
  # As in wireguard-go and Linux, the interface authorizes a claim only if
  # all of these conditions are true:
  #
  #   * The key is a configured key.
  #   * The timestamp is newer than all timestamps accepted from that key.
  #   * The initiation is not within 20 ms of the last initiation accepted
  #     from that key.
  #
  # The claim also admits the handoff of the worker against the small
  # handoff bound of the peer. This bound is separate from the inbound bound
  # of the peer. Thus frames sent to the index of a peer cannot push out the
  # handshakes that replace that index. The interface keeps accepted
  # timestamps for its full life, which is longer than the life of any peer
  # process. Thus a replay cannot follow the restart of a peer.
  #
  # The interface drops a handshake message (an initiation or a response)
  # without a reply if its MAC1 does not match the key of this interface.
  # As in wireguard-go and Linux, the interface is under load in these
  # conditions, and for one second after them:
  #
  #   * At least one eighth of the initiation queue waits.
  #   * A worker cannot start.
  #
  # Under load, a handshake message must also have a MAC2 made with the
  # cookie for its source address (`Wagyu.Cookie`). A message without this
  # MAC2 gets a cookie reply, which costs no Noise work, and goes no
  # further. A message with this MAC2 continues only within the budget of
  # its source (`Wagyu.RateLimiter`). The cookie secret and the budgets are
  # bounded. The reply and the budget do not start a peer.
  #
  # Other messages have a receiver index (`Wagyu.IndexTable`). Peers
  # allocate and retire their indices here. The interface forwards a message
  # only to the live peer that holds its index. It drops a message with an
  # unknown or retired index. When a peer exits, each index that it held
  # becomes a tombstone.
  #
  # A peer that initiates a handshake gets its sender index and its
  # timestamp here together (`allocate_initiation/2`). The interface keeps
  # the last timestamp that it gave to each peer. Thus the initiation
  # timestamps of a peer increase strictly across restarts of its process.
  # Each timestamp is also later than the start time of the interface.
  #
  # A peer never sends an initiation before the wall-clock time in it. Thus
  # each timestamp sent before this interface started is at or before its
  # start time. As a result, the timestamps of this interface come after
  # the timestamps of all interfaces that ran before it. Only a wall clock
  # that moves back can break this rule. Then the timestamps are ahead of
  # the clock.
  #
  # Peers count their handshake events in the counters of the interface,
  # which they share. Thus `info/1` reports these events without a call to a
  # peer.
  #
  # The interface routes egress packets from the link by destination
  # through AllowedIPs. A peer is only a configuration record until it needs
  # a process. A peer needs a process for traffic or for an authorized
  # initiation. A peer with a persistent keepalive also needs one when the
  # peer supervisor starts. Then the interface starts the process of the
  # peer, monitors it, and forgets it when it exits.
  #
  # If a peer with a persistent keepalive exits, the interface starts it
  # again one second later. Only the interface starts peers. Thus there is a
  # maximum of one peer for each key.
  #
  # Each send to a peer is admitted against the bound of that peer first.
  # The interface drops and counts the messages that it cannot admit or
  # process. While the interface or the queue of a peer holds egress, that
  # egress counts against the credit of the link (`Wagyu.EgressCredit`).
  # Thus the stack sends no more than they have space for.
  #
  # The interface records the credit that each peer holds: the packets that
  # it admitted to the queue of the peer and did not retire yet. When the
  # peer takes a batch (`outbound_taken/2`), the interface retires the
  # packets that the queue no longer holds. When the peer goes, the
  # interface retires all of the credit of the peer.
  #
  # The peer changes only the count of its queue. Thus the record of the
  # interface is exact, however the peer exits. Each time the interface
  # retires credit, it tells the link.
  #
  # A peer that is idle for long enough to discard its keys asks the
  # interface to forget it (`release_peer/3`). After the interface forgets
  # the peer, the peer exits. The interface agrees only when no admitted
  # message for the peer still waits to reach it.
  #
  # In the same step, the interface no longer forwards messages to the peer,
  # and it retires the indices of the peer. Thus the exit causes no loss of
  # messages, and the next message starts a new process. The interface
  # keeps the endpoint of the peer, which the peer possibly learned from its
  # traffic. The interface starts the next process with that endpoint.
  #
  # Synchronous calls go in one direction only. Workers and peers can call
  # the interface. The interface calls only the supervisors that start
  # them, never a peer, a worker or the link.
  #
  # Time comes from `state.clock`, in monotonic milliseconds. Tests replace
  # it with a fake clock.

  use GenServer

  alias Wagyu.Admission
  alias Wagyu.AllowedIPs
  alias Wagyu.Config
  alias Wagyu.Cookie
  alias Wagyu.EgressCredit
  alias Wagyu.HandshakeQueue
  alias Wagyu.HandshakeSupervisor
  alias Wagyu.IndexTable
  alias Wagyu.IP
  alias Wagyu.Link
  alias Wagyu.Packet
  alias Wagyu.Packet.{CookieReply, Initiation, Response, Transport}
  alias Wagyu.PeerSupervisor
  alias Wagyu.RateLimiter
  alias Wagyu.TAI64N

  # The number of datagrams that the socket delivers before the interface
  # must arm it again.
  @active 32
  # The maximum egress that the link can have in the queue for the
  # interface at one time.
  @egress_packets 256
  @egress_bytes 512 * 1024
  # The bounds of the inbound queue and the outbound queue of each peer.
  # Each queue has its own bound. The same bound applies again to the
  # outbound packets that a peer holds while it has no key to send them.
  @peer_packets 128
  @peer_bytes 256 * 1024
  # The handoffs that can wait for a peer: one that the peer takes now, and
  # one more. A newer handshake replaces an older handshake. Thus a deeper
  # queue would only hold handshakes that the peer will discard.
  @peer_handoffs 2
  # A restarted interface binds the same port again. The socket of the
  # previous interface can hold the port for a short time after that
  # process was killed.
  @bind_attempts 10
  @bind_retry 10
  # OTP 27 gives a UDP socket an 8 KiB receive buffer. A burst of small
  # datagrams can overflow it while the interface is busy. OTP 28 uses the
  # OS default. The interface sets the size explicitly, to get the same
  # behavior on both. The kernel can set a lower limit.
  #
  # The buffer of the backend must hold the largest datagram completely. A
  # transport message is up to the MTU plus 32 bytes, and the MTU can be up
  # to 65,475.
  @recbuf 1_048_576
  @buffer 65_535
  # The socket backend sends from the calling process through the socket
  # NIF. For each datagram, it is about 25% faster than the inet driver.
  # Peers send their own datagrams on this socket. Thus they also get this
  # speed. Before OTP 27.2 (kernel 10.2), the backend sets `ipv6_v6only`
  # only after it binds, and this fails. Thus an IPv6 socket on those
  # versions uses the inet driver.
  @v6only_before_bind [10, 2]
  # The time after which the interface starts a failed peer with a
  # persistent keepalive again. Thus a peer that fails immediately at each
  # start cannot cause a tight restart loop.
  @peer_restart 1_000
  # The minimum time between two accepted initiations from one peer, in
  # milliseconds (50 each second, as in wireguard-go and Linux).
  @initiation_interval 20
  # The time for which the interface stays under load after the load stops
  # (UnderLoadAfterTime in wireguard-go).
  @under_load_after 1_000

  @counters [
    datagrams: 1,
    invalid_datagrams: 2,
    invalid_mac1: 3,
    initiations: 4,
    initiations_dropped: 5,
    initiations_failed: 6,
    initiations_unknown_peer: 7,
    initiations_replayed: 8,
    initiations_rate_limited: 9,
    initiations_unavailable: 10,
    initiations_accepted: 11,
    unknown_index: 12,
    inbound_routed: 13,
    inbound_peer_dropped: 14,
    egress_routed: 15,
    egress_unroutable: 16,
    egress_peer_dropped: 17,
    initiations_sent: 18,
    initiations_no_endpoint: 19,
    responses_sent: 20,
    responses_accepted: 21,
    responses_invalid: 22,
    keys_confirmed: 23,
    keepalives_sent: 24,
    transport_invalid: 25,
    send_errors: 26,
    transport_sent: 27,
    staged_dropped: 28,
    transport_received: 29,
    keepalives_received: 30,
    transport_replayed: 31,
    transport_expired: 32,
    transport_malformed: 33,
    transport_source_denied: 34,
    handshakes_abandoned: 35,
    cookie_replies_sent: 36,
    handshakes_rate_limited: 37,
    cookie_replies_accepted: 38,
    cookie_replies_invalid: 39
  ]

  # The counters that peers update.
  @peer_counters [
    :initiations_sent,
    :initiations_no_endpoint,
    :responses_sent,
    :responses_accepted,
    :responses_invalid,
    :keys_confirmed,
    :keepalives_sent,
    :transport_invalid,
    :send_errors,
    :transport_sent,
    :staged_dropped,
    :transport_received,
    :keepalives_received,
    :transport_replayed,
    :transport_expired,
    :transport_malformed,
    :transport_source_denied,
    :handshakes_abandoned,
    :cookie_replies_accepted,
    :cookie_replies_invalid
  ]

  @claim_errors [
    unknown_peer: :initiations_unknown_peer,
    replayed: :initiations_replayed,
    rate_limited: :initiations_rate_limited,
    unavailable: :initiations_unavailable
  ]

  @spec start_link({pid(), Config.t()}) :: GenServer.on_start()
  def start_link({root, %Config{} = config}), do: GenServer.start_link(__MODULE__, {root, config})

  @doc """
  Admits egress packets from the link and sends them to the interface of
  `root`, in sequence. Returns two values:

    * the number of packets refused because the queue was full or no
      interface runs
    * the interface, queue and credit count that took the other packets

  The link uses these values to account for the packets. It grants their
  credit back when they leave, or when that interface exits.
  """
  @spec deliver(term(), [binary()]) :: {non_neg_integer(), {pid(), Admission.t(), EgressCredit.t()} | nil}
  def deliver(root, packets) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, %{egress: egress, credit: credit}} ->
        {admitted, refused} = Admission.admit_prefix(egress, packets)
        EgressCredit.take(credit, admitted)
        if admitted != [], do: send(interface, {:wg_egress, admitted})
        {refused, {interface, egress, credit}}

      :error ->
        {length(packets), nil}
    end
  end

  @doc "Returns the public state of the interface, or `:error` if the interface does not run."
  @spec info(pid()) :: {:ok, map()} | :error
  def info(interface) do
    GenServer.call(interface, :info)
  catch
    :exit, _reason -> :error
  end

  @doc """
  Claims the peer for an initiation that a handshake worker authenticated.
  Returns the process of the peer and its configuration, which holds its
  preshared key. The reply contains the configuration, not the bare key,
  because the `sys` debug log records replies without changes. Thus the
  log formats the key only through the `Inspect` implementation of
  `Wagyu.Config.Peer`, which omits the key.

  The claim is atomic. The interface of `root` does these steps:

    1. It authorizes `remote_key` against the configuration.
    2. It authorizes `timestamp` against the greatest timestamp that it
       accepted for that key.
    3. It applies the rate limit to the key.
    4. It gets or starts the one peer process for the key.
    5. It admits the handoff against the handoff bound of that peer. The
       caller must then send this handoff.

  The interface records the timestamp only if all of these steps are
  successful. The errors are:

    * `:unknown_peer`
    * `:replayed` - the timestamp is not strictly greater
    * `:rate_limited` - the initiation is within 20 ms of the last one
      accepted for the key
    * `:unavailable` - the peer cannot start, or it already has the maximum
      number of handoffs that can wait, or no interface runs

  The call has no timeout, because a caller that abandoned the call could
  leave an admitted handoff that is never sent. A wait without a timeout
  cannot cause a deadlock, because the interface never calls workers or
  peers.
  """
  @spec claim_peer(term(), <<_::256>>, TAI64N.t()) ::
          {:ok, pid(), Config.Peer.t()} | {:error, :unknown_peer | :replayed | :rate_limited | :unavailable}
  def claim_peer(root, remote_key, <<_::binary-12>> = timestamp) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, _value} -> GenServer.call(interface, {:claim_peer, remote_key, timestamp}, :infinity)
      :error -> {:error, :unavailable}
    end
  catch
    :exit, _reason -> {:error, :unavailable}
  end

  @doc """
  Allocates a local receiver index for the calling peer, which is the
  running peer for `public_key`. The interface forwards messages for the
  index to that peer until the peer retires the index or exits. Returns
  `:error` if the caller is not that peer, or if no interface runs. The call
  has no timeout, the same as `claim_peer/3`. Thus the interface never
  allocates an index to a caller that no longer waits for it.
  """
  @spec allocate_index(term(), <<_::256>>) :: {:ok, IndexTable.index()} | :error
  def allocate_index(root, public_key) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, _value} -> GenServer.call(interface, {:allocate_index, public_key}, :infinity)
      :error -> :error
    end
  catch
    :exit, _reason -> :error
  end

  @doc """
  Allocates a local sender index, the same as `allocate_index/2`. It also
  allocates the timestamp for the next initiation of the calling peer.

  The timestamp is the wall-clock time if that time is later than these
  two times:

    * the last timestamp that this interface gave to the peer
    * the start time of the interface

  If not, the timestamp is the next one after the later of these two times
  (`Wagyu.TAI64N.next/2`). This timestamp can be slightly ahead of the wall
  clock. Returns `:error` if the caller is not the running peer for
  `public_key`, or if no interface runs.
  """
  @spec allocate_initiation(term(), <<_::256>>) :: {:ok, IndexTable.index(), TAI64N.t()} | :error
  def allocate_initiation(root, public_key) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, _value} -> GenServer.call(interface, {:allocate_initiation, public_key}, :infinity)
      :error -> :error
    end
  catch
    :exit, _reason -> :error
  end

  @doc """
  Counts an event of a peer in the `counters` of its interface. The
  interface gives these counters to each peer that it starts. `name` is one
  of the peer counters in `t:Wagyu.info/0`.
  """
  @spec count_peer_event(:counters.counters_ref(), atom(), non_neg_integer()) :: :ok
  def count_peer_event(counters, name, increment \\ 1) when name in @peer_counters,
    do: :counters.add(counters, Keyword.fetch!(@counters, name), increment)

  @doc """
  Tells the interface of `root` that the calling peer took outbound packets
  from its queue. The calling peer is the running peer for `public_key`.
  The egress credit of these packets is then free again.
  """
  @spec outbound_taken(term(), <<_::256>>) :: :ok
  def outbound_taken(root, public_key) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, _value} -> send(interface, {:wg_outbound_taken, public_key, self()})
      :error -> :ok
    end

    :ok
  end

  @doc """
  Forgets the calling peer, which is the running peer for `public_key`.
  The peer then exits. The interface retires its indices. The next traffic
  for the key starts a new process, with `endpoint` as its endpoint if
  `endpoint` is not `nil`.

  Returns `:busy`, and forgets nothing, while admitted messages for the
  peer still wait for it to take them. Also returns `:ok` if the caller is
  not that peer, or if no interface runs, because nothing will go to the
  caller in either case.
  """
  @spec release_peer(term(), <<_::256>>, {:inet.ip_address(), :inet.port_number()} | nil) :: :ok | :busy
  def release_peer(root, public_key, endpoint) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, _value} -> GenServer.call(interface, {:release_peer, public_key, endpoint}, :infinity)
      :error -> :ok
    end
  catch
    :exit, _reason -> :ok
  end

  @doc """
  Retires a local receiver index that the calling peer holds. The index
  becomes a drop-only tombstone and is not allocated again for 180 seconds.
  Anything else is ignored.
  """
  @spec retire_index(term(), IndexTable.index()) :: :ok
  def retire_index(root, index) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, _value} -> GenServer.call(interface, {:retire_index, index})
      :error -> :ok
    end
  catch
    :exit, _reason -> :ok
  end

  @impl true
  def init({root, %Config{} = config}) do
    # Trap exits so that terminate/2 closes the socket on shutdown.
    Process.flag(:trap_exit, true)

    case open_socket(config.listen) do
      {:ok, socket, port} ->
        egress = Admission.new(@egress_packets, @egress_bytes)
        credit = EgressCredit.new()
        :ok = Wagyu.Registry.register(root, :interface, %{egress: egress, credit: credit})

        {:ok,
         %{
           root: root,
           config: config,
           socket: socket,
           # The socket of the backend has no Erlang link to its owner.
           # Thus a monitor reports that it closed.
           socket_monitor: :inet.monitor(socket),
           port: port,
           mac1_key: Packet.mac1_key(config.public_key),
           egress: egress,
           credit: credit,
           counters: :counters.new(length(@counters), []),
           handshakes: HandshakeQueue.new(),
           cookies: Cookie.checker(config.public_key),
           limiter: RateLimiter.new(),
           under_load_until: nil,
           peers: %{},
           endpoints: %{},
           monitors: %{},
           initiations: %{},
           sent: %{},
           started: TAI64N.now(),
           indices: IndexTable.new(),
           expiry_timer: nil,
           clock: fn -> System.monotonic_time(:millisecond) end
         }}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call(:info, _from, state) do
    info = %{
      public_key: state.config.public_key,
      listen: %{state.config.listen | port: state.port},
      counters: Map.new(@counters, fn {name, index} -> {name, :counters.get(state.counters, index)} end),
      peers:
        state.config.peers
        |> Map.values()
        |> Enum.sort_by(& &1.public_key)
        |> Enum.map(fn peer ->
          %{
            public_key: peer.public_key,
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips,
            running: Map.has_key?(state.peers, peer.public_key)
          }
        end)
    }

    {:reply, {:ok, info}, state}
  end

  def handle_call({:claim_peer, key, timestamp}, _from, state) do
    now = state.clock.()

    with {:ok, config} <- authorize(state, key, timestamp, now),
         {:ok, peer, state} <- ensure_peer(state, key),
         :ok <- admit_handoff(peer, state) do
      count(state, :initiations_accepted)
      initiations = Map.put(state.initiations, key, %{timestamp: timestamp, accepted_at: now})
      {:reply, {:ok, peer.pid, config}, %{state | initiations: initiations}}
    else
      {:error, reason} when is_atom(reason) -> reject_claim(state, reason)
      {:error, state} -> reject_claim(state, :unavailable)
    end
  end

  def handle_call({:allocate_index, key}, {caller, _tag}, state) do
    case allocate(state, key, caller) do
      {:ok, index, state} -> {:reply, {:ok, index}, state}
      :error -> {:reply, :error, state}
    end
  end

  def handle_call({:allocate_initiation, key}, {caller, _tag}, state) do
    case allocate(state, key, caller) do
      {:ok, index, state} ->
        timestamp = TAI64N.next(Map.get(state.sent, key, state.started))
        {:reply, {:ok, index, timestamp}, %{state | sent: Map.put(state.sent, key, timestamp)}}

      :error ->
        {:reply, :error, state}
    end
  end

  def handle_call({:release_peer, key, endpoint}, {caller, _tag}, state) do
    case state.peers do
      %{^key => %{pid: ^caller} = peer} ->
        if idle?(peer) do
          {:reply, :ok, release(state, key, caller, endpoint)}
        else
          {:reply, :busy, state}
        end

      _not_this_peer ->
        {:reply, :ok, state}
    end
  end

  def handle_call({:retire_index, index}, {caller, _tag}, state) do
    case IndexTable.lookup(state.indices, index) do
      {:active, {_key, ^caller}} ->
        indices = IndexTable.retire(state.indices, index, state.clock.())
        {:reply, :ok, schedule_expiry(%{state | indices: indices})}

      _not_held ->
        {:reply, :ok, state}
    end
  end

  @impl true
  def handle_info({:udp, socket, address, port, datagram}, %{socket: socket} = state) do
    count(state, :datagrams)
    {:noreply, receive_datagram(state, datagram, {address, port})}
  end

  def handle_info({:udp_passive, socket}, %{socket: socket} = state) do
    :ok = :inet.setopts(socket, active: @active)
    {:noreply, state}
  end

  # The interface routes the batch first. Then it forwards the share of each
  # peer as one message, in sequence. Each packet stays admitted until the
  # interface drops or forwards it. Thus, if the interface dies during a
  # batch, the link counts the remaining packets as dropped. Only the share
  # that the interface forwards at that instant can be counted two times.
  def handle_info({:wg_egress, packets}, state) do
    {state, forwarded} = packets |> route(state) |> Enum.reduce({state, 0}, &forward/2)
    # The interface dropped the other packets, and the link can grant their
    # credit again.
    if forwarded < length(packets), do: retired(state)
    {:noreply, state}
  end

  def handle_info({:wg_outbound_taken, key, pid}, state) do
    case state.peers do
      %{^key => %{pid: ^pid}} -> {:noreply, settle_peer(state, key)}
      _not_this_peer -> {:noreply, state}
    end
  end

  def handle_info({:DOWN, monitor, :process, pid, reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {:worker, monitors} ->
        # A worker exits normally after its claim is complete, and the claim
        # was counted at that time. All other exits mean that its initiation
        # failed.
        if reason != :normal, do: count(state, :initiations_failed)
        {:noreply, worker_done(%{state | monitors: monitors})}

      {{:peer, key}, monitors} ->
        {:noreply, peer_down(%{state | monitors: monitors}, key, pid)}

      {nil, _monitors} ->
        {:noreply, state}
    end
  end

  # The peer supervisor started or restarted. Peers with a persistent
  # keepalive start with it.
  def handle_info(:peer_supervisor_started, state) do
    {:noreply,
     state.config.peers
     |> Map.values()
     |> Enum.filter(&(&1.persistent_keepalive > 0))
     |> Enum.reduce(state, fn peer, state ->
       case ensure_peer(state, peer.public_key) do
         {:ok, _peer, state} -> state
         {:error, state} -> state
       end
     end)}
  end

  def handle_info({:restart_peer, key}, state) do
    case ensure_peer(state, key) do
      {:ok, _peer, state} -> {:noreply, state}
      {:error, state} -> {:noreply, state}
    end
  end

  def handle_info(:expire_indices, state) do
    if state.expiry_timer, do: Process.cancel_timer(state.expiry_timer)
    indices = IndexTable.expire(state.indices, state.clock.())
    {:noreply, schedule_expiry(%{state | indices: indices, expiry_timer: nil})}
  end

  def handle_info({:DOWN, monitor, _type, _socket, reason}, %{socket_monitor: monitor} = state),
    do: {:stop, {:shutdown, {:socket_closed, reason}}, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  # A socket that closed a short time ago can exit before it answers the
  # close.
  def terminate(_reason, state) do
    :gen_udp.close(state.socket)
  catch
    :exit, _reason -> :ok
  end

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:config, :cookies], &redact_reply/1)

  # The reply to a claim contains the preshared key of the peer.
  defp redact_reply({:ok, peer, %Config.Peer{}}), do: {:ok, peer, :redacted}
  defp redact_reply(reply), do: reply

  # Inbound datagrams

  defp receive_datagram(state, datagram, source) do
    case Packet.decode(datagram) do
      {:ok, %Initiation{sender_index: sender}} ->
        handshake(state, datagram, source, sender, &initiation/3)

      {:ok, %Response{sender_index: sender, receiver_index: index}} ->
        handshake(state, datagram, source, sender, &indexed(&1, index, &2, &3))

      {:ok, %CookieReply{receiver_index: index}} ->
        indexed(state, index, datagram, source)

      {:ok, %Transport{receiver_index: index}} ->
        indexed(state, index, datagram, source)

      {:error, _reason} ->
        count(state, :invalid_datagrams, state)
    end
  end

  # The interface checks MAC1 first. Then, under load, it checks MAC2 and
  # the budget of the source. After that, `accept` processes the message.
  defp handshake(state, frame, source, sender_index, accept) do
    if Packet.valid_mac1?(frame, state.mac1_key) do
      now = state.clock.()
      state = if HandshakeQueue.loaded?(state.handshakes), do: under_load(state, now), else: state

      if under_load?(state, now),
        do: screen(state, frame, source, sender_index, accept, now),
        else: accept.(state, frame, source)
    else
      count(state, :invalid_mac1, state)
    end
  end

  defp screen(state, frame, {address, port} = source, sender_index, accept, now) do
    if Cookie.valid_mac2?(state.cookies, frame, source, now) do
      case RateLimiter.allow(state.limiter, address, now) do
        {:ok, limiter} -> accept.(%{state | limiter: limiter}, frame, source)
        {:limited, limiter} -> count(state, :handshakes_rate_limited, %{state | limiter: limiter})
      end
    else
      {reply, cookies} = Cookie.reply(state.cookies, frame, sender_index, source, now)
      state = %{state | cookies: cookies}

      case :gen_udp.send(state.socket, address, port, reply) do
        :ok -> count(state, :cookie_replies_sent, state)
        {:error, _reason} -> count(state, :send_errors, state)
      end
    end
  end

  defp under_load(state, now), do: %{state | under_load_until: now + @under_load_after}

  defp under_load?(%{under_load_until: until}, now), do: is_integer(until) and now < until

  defp initiation(state, datagram, source) do
    case HandshakeQueue.admit(state.handshakes, %{frame: datagram, source: source}) do
      {:start, candidate, handshakes} -> start_worker(%{state | handshakes: handshakes}, candidate)
      {:queued, handshakes} -> %{state | handshakes: handshakes}
      :full -> count(state, :initiations_dropped, state)
    end
  end

  # A message goes only to the live peer that holds its index, within the
  # inbound bound of that peer. A retired index is a tombstone, and its
  # messages drop the same as for an unknown index. The interface retires an
  # index when it processes the exit of its peer. Thus the peer check covers
  # the time before that.
  defp indexed(state, index, frame, source) do
    with {:active, {key, pid}} <- IndexTable.lookup(state.indices, index),
         %{^key => %{pid: ^pid} = peer} <- state.peers do
      case Admission.admit(peer.inbound, 1, byte_size(frame)) do
        :ok ->
          send(pid, {:wg_frame, index, frame, source})
          count(state, :inbound_routed, state)

        :full ->
          count(state, :inbound_peer_dropped, state)
      end
    else
      _unknown_or_retired -> count(state, :unknown_index, state)
    end
  end

  defp start_worker(state, candidate) do
    case HandshakeSupervisor.start_worker(state.root, candidate) do
      {:ok, worker} ->
        count(state, :initiations)
        %{state | monitors: Map.put(state.monitors, Process.monitor(worker), :worker)}

      # If no worker can run it, the handshake capacity is fully used.
      {:error, _reason} ->
        count(state, :initiations_dropped)
        state |> under_load(state.clock.()) |> worker_done()
    end
  end

  # Load continues for one second after it stops. The load can stop here,
  # when a worker releases its slot and no datagram arrives to detect the
  # change.
  defp worker_done(state) do
    state = if HandshakeQueue.loaded?(state.handshakes), do: under_load(state, state.clock.()), else: state

    case HandshakeQueue.release(state.handshakes) do
      {:start, candidate, handshakes} -> start_worker(%{state | handshakes: handshakes}, candidate)
      {:idle, handshakes} -> %{state | handshakes: handshakes}
    end
  end

  # Indices

  defp allocate(state, key, caller) do
    case state.peers do
      %{^key => %{pid: ^caller}} ->
        {index, indices} = IndexTable.allocate(state.indices, {key, caller})
        {:ok, index, %{state | indices: indices}}

      _not_this_peer ->
        :error
    end
  end

  # Claims

  defp authorize(state, key, timestamp, now) do
    case {Config.fetch_peer(state.config, key), state.initiations} do
      {{:error, :unknown_peer} = error, _initiations} ->
        error

      {{:ok, peer}, %{^key => last}} ->
        cond do
          not TAI64N.after?(timestamp, last.timestamp) -> {:error, :replayed}
          now - last.accepted_at < @initiation_interval -> {:error, :rate_limited}
          true -> {:ok, peer}
        end

      {{:ok, peer}, _first} ->
        {:ok, peer}
    end
  end

  # If a peer empties its mailbox slowly, it refuses new handshakes. It does
  # not queue them without a limit. Handoffs are counted only in messages.
  # The peer releases each handoff when it takes it. If a handoff is still
  # in the queue when the peer exits, the handoff is discarded with the
  # peer. It was already counted as accepted.
  defp admit_handoff(peer, state) do
    case Admission.admit(peer.handoffs, 1, 0) do
      :ok -> :ok
      :full -> {:error, state}
    end
  end

  defp reject_claim(state, reason) do
    count(state, Keyword.fetch!(@claim_errors, reason))
    {:reply, {:error, reason}, state}
  end

  # Egress

  # Groups routable packets by peer. The packets of each peer stay in
  # sequence, and the peers are in the sequence of their first packets.
  # Unroutable packets are dropped here.
  defp route(packets, state) do
    {keys, shares} =
      Enum.reduce(packets, {[], %{}}, fn packet, {keys, shares} ->
        case destination(state, packet) do
          {:ok, key} when is_map_key(shares, key) -> {keys, Map.update!(shares, key, &[packet | &1])}
          {:ok, key} -> {[key | keys], Map.put(shares, key, [packet])}
          :error -> {keys, shares}
        end
      end)

    keys |> Enum.reverse() |> Enum.map(&{&1, Enum.reverse(Map.fetch!(shares, &1))})
  end

  defp destination(state, packet) do
    with {:ok, %{destination: destination, length: length}} when length == byte_size(packet) <- IP.parse(packet),
         {:ok, _key} = routed <- AllowedIPs.lookup(state.config.allowed_ips, destination) do
      routed
    else
      _unroutable ->
        count(state, :egress_unroutable)
        Admission.release(state.egress, 1, byte_size(packet))
        EgressCredit.retire(state.credit, 1, byte_size(packet))
        :error
    end
  end

  # The packets of a peer are admitted in sequence until one does not fit,
  # the same as the link admits egress. They go to the peer as one message.
  defp forward({key, packets}, {state, forwarded}) do
    {admitted, state} =
      case ensure_peer(state, key) do
        {:ok, peer, state} ->
          {admitted, _refused} = Admission.admit_prefix(peer.outbound, packets)
          if admitted != [], do: send(peer.pid, {:wg_outbound, admitted})
          {credited_packets, credited_bytes} = peer.credited
          credited = {credited_packets + length(admitted), credited_bytes + Admission.bytes(admitted)}
          {length(admitted), put_in(state.peers[key].credited, credited)}

        {:error, state} ->
          {0, state}
      end

    add(state, :egress_routed, admitted)
    add(state, :egress_peer_dropped, length(packets) - admitted)
    Admission.release_all(state.egress, packets)
    EgressCredit.retire_all(state.credit, Enum.drop(packets, admitted))
    {state, forwarded + admitted}
  end

  # Tells the link that egress credit is free again.
  defp retired(state) do
    with {:ok, link} <- Link.lookup(state.root), do: Link.retired(link)
  end

  # Retires the credit for the packets that the queue of the peer no longer
  # holds. Only the peer releases packets from the queue. Thus its count can
  # only decrease between reads, and the retired packets are out of the
  # queue.
  defp settle_peer(state, key) do
    peer = Map.fetch!(state.peers, key)
    {held_packets, held_bytes} = Admission.usage(peer.outbound)
    {credited_packets, credited_bytes} = peer.credited
    taken = {credited_packets - held_packets, credited_bytes - held_bytes}

    if taken == {0, 0} do
      state
    else
      EgressCredit.retire(state.credit, elem(taken, 0), elem(taken, 1))
      retired(state)
      put_in(state.peers[key].credited, {held_packets, held_bytes})
    end
  end

  # Retires all of the credit that a forgotten peer still holds.
  defp retire_peer(state, peer) do
    {credited_packets, credited_bytes} = peer.credited
    EgressCredit.retire(state.credit, credited_packets, credited_bytes)
    if peer.credited != {0, 0}, do: retired(state)
  end

  # Returns the process of the peer, and starts it if it does not run.
  # Egress and claims both come here, and only the interface starts peers.
  # Thus there is a maximum of one peer for each key.
  defp ensure_peer(%{peers: peers} = state, key) when is_map_key(peers, key), do: {:ok, Map.fetch!(peers, key), state}

  defp ensure_peer(state, key) do
    {:ok, config} = Config.fetch_peer(state.config, key)
    inbound = Admission.new(@peer_packets, @peer_bytes)
    outbound = Admission.new(@peer_packets, @peer_bytes)
    staging = Admission.new(@peer_packets, @peer_bytes)
    handoffs = Admission.new(@peer_handoffs, 1)

    args = %{
      root: state.root,
      peer: config,
      allowed_ips: AllowedIPs.source_filter(state.config.allowed_ips, key),
      endpoint: Map.get(state.endpoints, key),
      socket: state.socket,
      counters: state.counters,
      inbound: inbound,
      outbound: outbound,
      staging: staging,
      handoffs: handoffs
    }

    case PeerSupervisor.start_peer(state.root, args) do
      {:ok, pid} ->
        monitor = Process.monitor(pid)

        peer = %{
          pid: pid,
          inbound: inbound,
          outbound: outbound,
          staging: staging,
          handoffs: handoffs,
          credited: {0, 0}
        }

        {:ok, peer,
         %{state | peers: Map.put(state.peers, key, peer), monitors: Map.put(state.monitors, monitor, {:peer, key})}}

      {:error, _reason} ->
        {:error, state}
    end
  end

  # Some packets were admitted to a peer that did not take them, or that
  # staged them and did not send them. These packets are lost with the
  # peer, and the counts of its queues give their number. All of the credit
  # that the peer held is free again. Its indices become tombstones. Thus
  # messages for them drop here, and the interface does not use them again
  # while the remote party can still send to them.
  #
  # The interface already forgot a released peer, and a different process
  # can now hold its key.
  defp peer_down(state, key, pid) do
    case state.peers do
      %{^key => %{pid: ^pid} = peer} ->
        {lost_outbound, _bytes} = Admission.usage(peer.outbound)
        {lost_staged, _bytes} = Admission.usage(peer.staging)
        {lost_inbound, _bytes} = Admission.usage(peer.inbound)
        add(state, :egress_peer_dropped, lost_outbound + lost_staged)
        retire_peer(state, peer)
        add(state, :inbound_peer_dropped, lost_inbound)
        indices = IndexTable.retire_owner(state.indices, {key, pid}, state.clock.())
        {:ok, config} = Config.fetch_peer(state.config, key)
        if config.persistent_keepalive > 0, do: Process.send_after(self(), {:restart_peer, key}, @peer_restart)
        schedule_expiry(%{state | peers: Map.delete(state.peers, key), indices: indices})

      _released ->
        state
    end
  end

  defp release(state, key, pid, endpoint) do
    retire_peer(state, Map.fetch!(state.peers, key))
    indices = IndexTable.retire_owner(state.indices, {key, pid}, state.clock.())
    endpoints = if endpoint, do: Map.put(state.endpoints, key, endpoint), else: state.endpoints
    schedule_expiry(%{state | peers: Map.delete(state.peers, key), indices: indices, endpoints: endpoints})
  end

  defp idle?(peer) do
    Enum.all?([peer.inbound, peer.outbound, peer.staging, peer.handoffs], &match?({0, _bytes}, Admission.usage(&1)))
  end

  # One timer at a time, for the oldest tombstone.
  defp schedule_expiry(%{expiry_timer: nil} = state) do
    case IndexTable.next_expiry(state.indices) do
      nil ->
        state

      expires_at ->
        delay = max(expires_at - state.clock.(), 0)
        %{state | expiry_timer: Process.send_after(self(), :expire_indices, delay)}
    end
  end

  defp schedule_expiry(state), do: state

  # Socket

  defp open_socket(%{address: address, port: port}) do
    family = if tuple_size(address) == 4, do: [:inet], else: [:inet6, ipv6_v6only: true]
    # The backend option must come first.
    options = [{:inet_backend, inet_backend(address)}, :binary, ip: address, active: @active]
    options = options ++ [recbuf: @recbuf, buffer: @buffer] ++ family
    open_socket(port, options, @bind_attempts)
  end

  defp inet_backend(address) when tuple_size(address) == 4, do: :socket

  defp inet_backend(_address) do
    kernel = :kernel |> Application.spec(:vsn) |> to_string() |> String.split(".") |> Enum.map(&String.to_integer/1)
    if kernel >= @v6only_before_bind, do: :socket, else: :inet
  end

  defp open_socket(port, options, attempts) do
    case :gen_udp.open(port, options) do
      {:ok, socket} ->
        {:ok, bound} = :inet.port(socket)
        {:ok, socket, bound}

      {:error, :eaddrinuse} when port != 0 and attempts > 1 ->
        Process.sleep(@bind_retry)
        open_socket(port, options, attempts - 1)

      {:error, _reason} = error ->
        error
    end
  end

  defp count(state, name, result \\ :ok) do
    add(state, name, 1)
    result
  end

  defp add(state, name, increment), do: :counters.add(state.counters, Keyword.fetch!(@counters, name), increment)
end
