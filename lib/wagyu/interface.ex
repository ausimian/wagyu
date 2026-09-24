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
  # Egress packets from the link are routed by destination through
  # AllowedIPs. Peers are configuration records until traffic or an
  # authorized initiation needs one; the interface then starts its process,
  # monitors it, and forgets it when it exits. The interface is the only
  # process that starts peers, so there is at most one per key. Every send to
  # a peer is admitted against that peer's bound first. Messages that cannot
  # be admitted or acted on are dropped and counted.
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
  # Each peer's inbound and outbound queues, bounded separately.
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
  # The kernel may cap it lower. The driver's own buffer must hold the
  # largest datagram whole: a transport message is up to the MTU plus 32
  # bytes, and the MTU may be up to 65,475.
  @recbuf 1_048_576
  @buffer 65_535
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
    egress_peer_dropped: 17
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
  authenticated, returning the peer's process.

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
          {:ok, pid()} | {:error, :unknown_peer | :replayed | :rate_limited | :unavailable}
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
           port: port,
           mac1_key: Packet.mac1_key(config.public_key),
           egress: egress,
           counters: :counters.new(length(@counters), []),
           handshakes: HandshakeQueue.new(),
           peers: %{},
           monitors: %{},
           initiations: %{},
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

    with :ok <- authorize(state, key, timestamp, now),
         {:ok, peer, state} <- ensure_peer(state, key),
         :ok <- admit_handoff(peer, state) do
      count(state, :initiations_accepted)
      initiations = Map.put(state.initiations, key, %{timestamp: timestamp, accepted_at: now})
      {:reply, {:ok, peer.pid}, %{state | initiations: initiations}}
    else
      {:error, reason} when is_atom(reason) -> reject_claim(state, reason)
      {:error, state} -> reject_claim(state, :unavailable)
    end
  end

  def handle_call({:allocate_index, key}, {caller, _tag}, state) do
    case state.peers do
      %{^key => %{pid: ^caller}} ->
        {index, indices} = IndexTable.allocate(state.indices, {key, caller})
        {:reply, {:ok, index}, %{state | indices: indices}}

      _not_this_peer ->
        {:reply, :error, state}
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

  def handle_info(:expire_indices, state) do
    if state.expiry_timer, do: Process.cancel_timer(state.expiry_timer)
    indices = IndexTable.expire(state.indices, state.clock.())
    {:noreply, schedule_expiry(%{state | indices: indices, expiry_timer: nil})}
  end

  def handle_info({:EXIT, socket, reason}, %{socket: socket} = state),
    do: {:stop, {:shutdown, {:socket_closed, reason}}, state}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    :gen_udp.close(state.socket)
  end

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:config])

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

  # Claims

  defp authorize(state, key, timestamp, now) do
    case {Config.fetch_peer(state.config, key), state.initiations} do
      {{:error, :unknown_peer} = error, _initiations} ->
        error

      {{:ok, _peer}, %{^key => last}} ->
        cond do
          not TAI64N.after?(timestamp, last.timestamp) -> {:error, :replayed}
          now - last.accepted_at < @initiation_interval -> {:error, :rate_limited}
          true -> :ok
        end

      {{:ok, _peer}, _first} ->
        :ok
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
    handoffs = Admission.new(@peer_handoffs, 1)

    args = %{
      root: state.root,
      peer: config,
      socket: state.socket,
      inbound: inbound,
      outbound: outbound,
      handoffs: handoffs
    }

    case PeerSupervisor.start_peer(state.root, args) do
      {:ok, pid} ->
        monitor = Process.monitor(pid)
        peer = %{pid: pid, inbound: inbound, outbound: outbound, handoffs: handoffs}

        {:ok, peer,
         %{state | peers: Map.put(state.peers, key, peer), monitors: Map.put(state.monitors, monitor, {:peer, key})}}

      {:error, _reason} ->
        {:error, state}
    end
  end

  # Packets admitted to a peer that it never took were lost with it; its
  # queues' counts say how many. Its indices become tombstones, so messages
  # for them drop here and none is reused while the remote party may still
  # send to it.
  defp peer_down(state, key, pid) do
    {peer, peers} = Map.pop!(state.peers, key)
    {lost_outbound, _bytes} = Admission.usage(peer.outbound)
    {lost_inbound, _bytes} = Admission.usage(peer.inbound)
    add(state, :egress_peer_dropped, lost_outbound)
    add(state, :inbound_peer_dropped, lost_inbound)
    indices = IndexTable.retire_owner(state.indices, {key, pid}, state.clock.())
    schedule_expiry(%{state | peers: peers, indices: indices})
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
    options = [:binary, ip: address, active: @active, recbuf: @recbuf, buffer: @buffer] ++ family
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
