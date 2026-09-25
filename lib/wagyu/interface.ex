defmodule Wagyu.Interface do
  @moduledoc false

  # The UDP socket owner and shallow demultiplexer.
  #
  # The interface owns the real UDP socket, the configuration and its
  # AllowedIPs routes, the table from configured public keys to running
  # peer processes, the local receiver-index table, and the greatest
  # initiation timestamp accepted from each peer. It does only fixed-size
  # work per datagram: decode, MAC1 screening, admission and an index
  # lookup. It never runs Noise.
  #
  # The socket is in bounded active mode: it delivers `@active` datagrams and
  # then waits for the interface to re-arm it, so datagrams never pile up in
  # the mailbox faster than they are handled. Valid initiations are admitted
  # to a bounded pool of handshake workers (`Wagyu.HandshakeQueue`), which
  # run Noise and then claim their peer here with `claim_peer/3`. A claim is
  # authorized only for a configured key whose timestamp is newer than any
  # accepted from it before, and not within 20 ms of the last initiation
  # accepted from it, as in wireguard-go and Linux. It also admits the
  # worker's handoff against the peer's own small handoff bound, apart from
  # the inbound bound, so frames sent to a peer's index cannot crowd out
  # the handshakes that would replace it. Accepted timestamps
  # outlive the peer process, so a replay cannot follow a peer's restart,
  # and last as long as this interface.
  #
  # Other messages are addressed by receiver index (`Wagyu.IndexTable`).
  # Peers allocate and retire their indices here; an index is forwarded only
  # to the live peer that holds it, and an unknown or retired index drops
  # here. When a peer exits, every index it held becomes a tombstone.
  #
  # A peer that initiates a handshake gets its sender index and timestamp
  # here together (`allocate_initiation/2`). The interface keeps the last
  # timestamp it gave each peer, so a peer's initiations are strictly
  # increasing across restarts of its process, and each is later than the
  # moment the interface started. A peer never sends an initiation before
  # the wall-clock time it names, so every timestamp sent before this
  # interface started is at or before that moment, and later ones follow
  # those of an interface that ran before it too. Only a wall clock that
  # steps back can break that: timestamps then run ahead of it.
  #
  # Peers count their handshake events in the interface's counters, which
  # they share, so `info/1` reports them without calling a peer.
  #
  # Egress packets from the link are routed by destination through
  # AllowedIPs. Peers are configuration records until traffic or an
  # authorized initiation needs one, or, for a peer with a persistent
  # keepalive, until the peer supervisor starts; the interface then starts
  # its process, monitors it, and forgets it when it exits. A peer with a
  # persistent keepalive that exits is started again a second later. The interface is
  # the only process that starts peers, so there is at most one per key.
  # Every send to a peer is admitted against that peer's bound first.
  # Messages that cannot be admitted or acted on are dropped and counted.
  #
  # A peer that has been idle long enough to discard its keys asks to be
  # forgotten (`release_peer/3`) and exits once it is. The interface agrees
  # only when nothing admitted for the peer is still waiting to reach it,
  # and it stops forwarding to the peer and retires its indices in the same
  # step, so no message is lost to the exit: whatever comes next starts a
  # new process. The interface keeps the endpoint the peer had, which may
  # have been learned from its traffic, and starts the next process with
  # it.
  #
  # Synchronous calls go one way: workers and peers may call the interface,
  # and the interface calls only the supervisors that start them, never a
  # peer, a worker or the link.
  #
  # Time comes from `state.clock`, monotonic milliseconds, which tests
  # replace with a fake clock.

  use GenServer

  alias Wagyu.Admission
  alias Wagyu.AllowedIPs
  alias Wagyu.Config
  alias Wagyu.HandshakeQueue
  alias Wagyu.HandshakeSupervisor
  alias Wagyu.IndexTable
  alias Wagyu.IP
  alias Wagyu.Packet
  alias Wagyu.Packet.{CookieReply, Initiation, Response, Transport}
  alias Wagyu.PeerSupervisor
  alias Wagyu.TAI64N

  # Datagrams the socket delivers before it must be re-armed.
  @active 32
  # Egress the link may have queued for the interface at once.
  @egress_packets 256
  @egress_bytes 512 * 1024
  # Each peer's inbound and outbound queues, bounded separately, and again
  # the outbound packets it holds while it has no key to send them with.
  @peer_packets 128
  @peer_bytes 256 * 1024
  # Handoffs waiting for a peer: one it is taking and one more. A newer
  # handshake replaces an older one, so a deeper queue would only hold
  # handshakes the peer is about to discard.
  @peer_handoffs 2
  # A restarted interface rebinds the same port, which its predecessor's
  # socket may hold for a moment after that process was killed.
  @bind_attempts 10
  @bind_retry 10
  # OTP 27 gives a UDP socket an 8 KiB receive buffer, which a burst of
  # small datagrams overflows while the interface is busy; OTP 28 leaves the
  # OS default. Set it explicitly so the interface behaves the same on both.
  # The kernel may cap it lower. The backend's own buffer must hold the
  # largest datagram whole: a transport message is up to the MTU plus 32
  # bytes, and the MTU may be up to 65,475.
  @recbuf 1_048_576
  @buffer 65_535
  # The socket backend sends from the calling process through the socket
  # NIF, about a quarter faster per datagram than the inet driver. Peers
  # send their own datagrams on this socket, so they get that too.
  @inet_backend :socket
  # How long after a peer with a persistent keepalive fails the interface
  # starts it again, so a peer that fails at once cannot spin.
  @peer_restart 1_000
  # The least time between two accepted initiations from one peer, in
  # milliseconds (wireguard-go's and Linux's 50 per second).
  @initiation_interval 20

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
    handshakes_abandoned: 35
  ]

  # The counters peers update.
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
    :handshakes_abandoned
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
  Admits egress packets from the link and sends them to `root`'s interface,
  in order. Returns how many were refused because its queue was full or no
  interface is running, and the interface and queue that took the rest, so
  that the link can account for them if that interface exits first.
  """
  @spec deliver(term(), [binary()]) :: {non_neg_integer(), {pid(), Admission.t()} | nil}
  def deliver(root, packets) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, %{egress: egress}} ->
        {admitted, refused} = Admission.admit_prefix(egress, packets)
        if admitted != [], do: send(interface, {:wg_egress, admitted})
        {refused, {interface, egress}}

      :error ->
        {length(packets), nil}
    end
  end

  @doc "Returns the interface's public state, or `:error` if it is not running."
  @spec info(pid()) :: {:ok, map()} | :error
  def info(interface) do
    GenServer.call(interface, :info)
  catch
    :exit, _reason -> :error
  end

  @doc """
  Claims the peer for an initiation that a handshake worker has
  authenticated, returning the peer's process and its configuration, which
  holds its preshared key. The configuration, rather than the bare key, is
  what the reply carries, so the `sys` debug log, which records replies
  as they are, formats the key only through `Wagyu.Config.Peer`'s
  `Inspect`, which omits it.

  The claim is atomic: `root`'s interface authorizes `remote_key` against the
  configuration and `timestamp` against the greatest one it has accepted for
  that key, rate-limits the key, gets or starts its one peer process, and
  admits the handoff the caller must then send against that peer's handoff
  bound. It records the timestamp only if all of that succeeds. The errors
  are `:unknown_peer`, `:replayed` for a timestamp that is not strictly
  greater, `:rate_limited` for an initiation within 20 ms of the last one
  accepted for the key, and `:unavailable` when the peer cannot start, has
  as many handoffs waiting as it may, or no interface is running.

  The call has no timeout. A caller that gave up could leave an admitted
  handoff that is never sent, and the interface never calls workers or
  peers, so it cannot be waiting on the caller.
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
  Allocates a local receiver index for the calling peer, the running peer
  for `public_key`. Messages addressed to the index are forwarded to that
  peer until it retires the index or exits. Returns `:error` if the caller
  is not that peer or no interface is running. Like `claim_peer/3`, the call
  has no timeout, so an index is never allocated to a caller that stopped
  waiting for it.
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
  Allocates a local sender index, as `allocate_index/2` does, and the
  timestamp for the calling peer's next initiation.

  The timestamp is the wall clock's when that is later than the last one
  this interface gave the peer and than the moment the interface started.
  Otherwise it is the next one after the later of those
  (`Wagyu.TAI64N.next/2`), which may be slightly ahead of the wall clock.
  Returns `:error` if the caller is not the running peer for `public_key`
  or no interface is running.
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
  Counts a peer's event in its interface's `counters`, which the interface
  gives each peer it starts. `name` is one of the peer counters in
  `t:Wagyu.info/0`.
  """
  @spec count_peer_event(:counters.counters_ref(), atom(), non_neg_integer()) :: :ok
  def count_peer_event(counters, name, increment \\ 1) when name in @peer_counters,
    do: :counters.add(counters, Keyword.fetch!(@counters, name), increment)

  @doc """
  Forgets the calling peer, the running peer for `public_key`, which then
  exits: traffic for it starts a new process, with `endpoint` as its
  endpoint unless that is nil, and its indices are retired.
  Returns `:busy`, and forgets nothing, while messages admitted for the
  peer are still waiting for it to take them. Returns `:ok` too if the
  caller is not that peer, or no interface is running, since nothing will
  be sent to it either way.
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
        :ok = Wagyu.Registry.register(root, :interface, %{egress: egress})

        {:ok,
         %{
           root: root,
           config: config,
           socket: socket,
           # The backend's socket is not linked to its owner, so a monitor
           # reports that it closed.
           socket_monitor: :inet.monitor(socket),
           port: port,
           mac1_key: Packet.mac1_key(config.public_key),
           egress: egress,
           counters: :counters.new(length(@counters), []),
           handshakes: HandshakeQueue.new(),
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

  # Each packet stays admitted until it has been routed, so if the interface
  # dies part-way through a batch the link counts the unrouted rest as
  # dropped. At most the one packet being routed at that instant may be
  # counted twice.
  def handle_info({:wg_egress, packets}, state) do
    {:noreply,
     Enum.reduce(packets, state, fn packet, state ->
       state = route(state, packet)
       Admission.release(state.egress, 1, byte_size(packet))
       state
     end)}
  end

  def handle_info({:DOWN, monitor, :process, pid, reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {:worker, monitors} ->
        # A worker exits normally once its claim is settled, and the claim
        # was counted then. Anything else means its initiation failed.
        if reason != :normal, do: count(state, :initiations_failed)
        {:noreply, worker_done(%{state | monitors: monitors})}

      {{:peer, key}, monitors} ->
        {:noreply, peer_down(%{state | monitors: monitors}, key, pid)}

      {nil, _monitors} ->
        {:noreply, state}
    end
  end

  # The peer supervisor has started, or restarted: peers with a persistent
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
  def terminate(_reason, state) do
    :gen_udp.close(state.socket)
  end

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:config], &redact_reply/1)

  # A claim's reply carries the peer's preshared key.
  defp redact_reply({:ok, peer, %Config.Peer{}}), do: {:ok, peer, :redacted}
  defp redact_reply(reply), do: reply

  # Inbound datagrams

  defp receive_datagram(state, datagram, source) do
    case Packet.decode(datagram) do
      {:ok, %Initiation{}} ->
        initiation(state, datagram, source)

      {:ok, %Response{receiver_index: index}} ->
        if Packet.valid_mac1?(datagram, state.mac1_key),
          do: indexed(state, index, datagram, source),
          else: count(state, :invalid_mac1, state)

      {:ok, %CookieReply{receiver_index: index}} ->
        indexed(state, index, datagram, source)

      {:ok, %Transport{receiver_index: index}} ->
        indexed(state, index, datagram, source)

      {:error, _reason} ->
        count(state, :invalid_datagrams, state)
    end
  end

  defp initiation(state, datagram, source) do
    if Packet.valid_mac1?(datagram, state.mac1_key) do
      case HandshakeQueue.admit(state.handshakes, %{frame: datagram, source: source}) do
        {:start, candidate, handshakes} -> start_worker(%{state | handshakes: handshakes}, candidate)
        {:queued, handshakes} -> %{state | handshakes: handshakes}
        :full -> count(state, :initiations_dropped, state)
      end
    else
      count(state, :invalid_mac1, state)
    end
  end

  # A message goes only to the live peer holding its index, within that
  # peer's inbound bound. A retired index is a tombstone and drops like an
  # unknown one. An index is retired when the interface processes its
  # peer's exit, so the peer check covers the moment before that.
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

      {:error, _reason} ->
        count(state, :initiations_dropped)
        worker_done(state)
    end
  end

  defp worker_done(state) do
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

  # A peer that is slow to drain its mailbox refuses new handshakes rather
  # than queueing them without limit. Handoffs are counted in messages
  # only. The peer releases each as it takes it; one still queued when the
  # peer exits is discarded with it, having been counted as accepted.
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

  defp route(state, packet) do
    with {:ok, %{destination: destination, length: length}} when length == byte_size(packet) <- IP.parse(packet),
         {:ok, key} <- AllowedIPs.lookup(state.config.allowed_ips, destination) do
      forward(state, key, packet)
    else
      _unroutable -> count(state, :egress_unroutable, state)
    end
  end

  defp forward(state, key, packet) do
    case ensure_peer(state, key) do
      {:ok, peer, state} ->
        case Admission.admit(peer.outbound, 1, byte_size(packet)) do
          :ok ->
            send(peer.pid, {:wg_outbound, packet})
            count(state, :egress_routed, state)

          :full ->
            count(state, :egress_peer_dropped, state)
        end

      {:error, state} ->
        count(state, :egress_peer_dropped, state)
    end
  end

  # Returns the peer's process, starting it if it is not running. Egress and
  # claims both come here, and the interface is the only process that starts
  # peers, so there is at most one per key.
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
        peer = %{pid: pid, inbound: inbound, outbound: outbound, staging: staging, handoffs: handoffs}

        {:ok, peer,
         %{state | peers: Map.put(state.peers, key, peer), monitors: Map.put(state.monitors, monitor, {:peer, key})}}

      {:error, _reason} ->
        {:error, state}
    end
  end

  # Packets admitted to a peer that it never took, or that it staged and
  # never sent, were lost with it; its queues' counts say how many. Its indices become tombstones, so messages
  # for them drop here and none is reused while the remote party may still
  # send to it.
  #
  # A peer that was released has been forgotten already, and another
  # process may hold its key by now.
  defp peer_down(state, key, pid) do
    case state.peers do
      %{^key => %{pid: ^pid} = peer} ->
        {lost_outbound, _bytes} = Admission.usage(peer.outbound)
        {lost_staged, _bytes} = Admission.usage(peer.staging)
        {lost_inbound, _bytes} = Admission.usage(peer.inbound)
        add(state, :egress_peer_dropped, lost_outbound + lost_staged)
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
    options = [{:inet_backend, @inet_backend}, :binary, ip: address, active: @active, recbuf: @recbuf, buffer: @buffer]
    options = options ++ family
    open_socket(port, options, @bind_attempts)
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
