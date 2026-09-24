defmodule Wagyu.Interface do
  @moduledoc false

  # The UDP socket owner and shallow demultiplexer.
  #
  # The interface owns the real UDP socket, the configuration and its
  # AllowedIPs routes, and the table from configured public keys to running
  # peer processes. It does only fixed-size work per datagram: decode, MAC1
  # screening and admission. It never runs Noise.
  #
  # The socket is in bounded active mode: it delivers `@active` datagrams and
  # then waits for the interface to re-arm it, so datagrams never pile up in
  # the mailbox faster than they are handled. Valid initiations are admitted
  # to a bounded pool of handshake workers (`Wagyu.HandshakeQueue`). Other
  # messages are addressed by receiver index; indices are allocated by
  # handshakes, so until those exist no index is live and such messages are
  # dropped here, before reaching any peer.
  #
  # Egress packets from the link are routed by destination through
  # AllowedIPs. Peers are configuration records until traffic needs one; the
  # first packet for a peer starts its process, and the interface monitors it
  # and forgets it when it exits. Every send to a peer is admitted against
  # that peer's bound first. Messages that cannot be admitted or acted on are
  # dropped and counted.
  #
  # Synchronous calls go one way: workers and peers may call the interface,
  # and the interface calls only the supervisors that start them, never a
  # peer, a worker or the link.

  use GenServer

  alias Wagyu.Admission
  alias Wagyu.AllowedIPs
  alias Wagyu.Config
  alias Wagyu.HandshakeQueue
  alias Wagyu.HandshakeSupervisor
  alias Wagyu.IP
  alias Wagyu.Packet
  alias Wagyu.Packet.{CookieReply, Initiation, Response, Transport}
  alias Wagyu.PeerSupervisor

  # Datagrams the socket delivers before it must be re-armed.
  @active 32
  # Egress the link may have queued for the interface at once.
  @egress_packets 256
  @egress_bytes 512 * 1024
  # Each peer's inbound and outbound queues, bounded separately.
  @peer_packets 128
  @peer_bytes 256 * 1024
  # A restarted interface rebinds the same port, which its predecessor's
  # socket may hold for a moment after that process was killed.
  @bind_attempts 10
  @bind_retry 10

  @counters [
    datagrams: 1,
    invalid_datagrams: 2,
    invalid_mac1: 3,
    initiations: 4,
    initiations_dropped: 5,
    unknown_index: 6,
    egress_routed: 7,
    egress_unroutable: 8,
    egress_peer_dropped: 9
  ]

  @spec start_link({pid(), Config.t()}) :: GenServer.on_start()
  def start_link({root, %Config{} = config}), do: GenServer.start_link(__MODULE__, {root, config})

  @doc """
  Admits egress packets from the link and sends them to `root`'s interface,
  in order. Returns how many were refused because its queue was full or no
  interface is running.
  """
  @spec deliver(term(), [binary()]) :: non_neg_integer()
  def deliver(root, packets) do
    case Wagyu.Registry.lookup(root, :interface) do
      {:ok, interface, %{egress: egress}} ->
        {admitted, refused} = Admission.admit_prefix(egress, packets)
        if admitted != [], do: send(interface, {:wg_egress, admitted})
        refused

      :error ->
        length(packets)
    end
  end

  @doc "Returns the interface's public state, or `:error` if it is not running."
  @spec info(pid()) :: {:ok, map()} | :error
  def info(interface) do
    GenServer.call(interface, :info)
  catch
    :exit, _reason -> :error
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
           monitors: %{}
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

  @impl true
  def handle_info({:udp, socket, address, port, datagram}, %{socket: socket} = state) do
    count(state, :datagrams)
    {:noreply, receive_datagram(state, datagram, {address, port})}
  end

  def handle_info({:udp_passive, socket}, %{socket: socket} = state) do
    :ok = :inet.setopts(socket, active: @active)
    {:noreply, state}
  end

  def handle_info({:wg_egress, packets}, state) do
    Admission.release_all(state.egress, packets)
    {:noreply, Enum.reduce(packets, state, &route(&2, &1))}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {:worker, monitors} -> {:noreply, worker_done(%{state | monitors: monitors})}
      {{:peer, key}, monitors} -> {:noreply, %{state | monitors: monitors, peers: Map.delete(state.peers, key)}}
      {nil, _monitors} -> {:noreply, state}
    end
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
          do: indexed(state, index),
          else: count(state, :invalid_mac1, state)

      {:ok, %CookieReply{receiver_index: index}} ->
        indexed(state, index)

      {:ok, %Transport{receiver_index: index}} ->
        indexed(state, index)

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

  # No receiver index is allocated yet, so none can be live.
  defp indexed(state, _index), do: count(state, :unknown_index, state)

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

  # Returns the peer's process, starting it if it is not running. The
  # interface is the only process that starts peers, so there is at most one
  # per key.
  defp ensure_peer(%{peers: peers} = state, key) when is_map_key(peers, key), do: {:ok, Map.fetch!(peers, key), state}

  defp ensure_peer(state, key) do
    {:ok, config} = Config.fetch_peer(state.config, key)
    inbound = Admission.new(@peer_packets, @peer_bytes)
    outbound = Admission.new(@peer_packets, @peer_bytes)
    args = %{root: state.root, peer: config, socket: state.socket, inbound: inbound, outbound: outbound}

    case PeerSupervisor.start_peer(state.root, args) do
      {:ok, pid} ->
        monitor = Process.monitor(pid)
        peer = %{pid: pid, inbound: inbound, outbound: outbound}

        {:ok, peer,
         %{state | peers: Map.put(state.peers, key, peer), monitors: Map.put(state.monitors, monitor, {:peer, key})}}

      {:error, _reason} ->
        {:error, state}
    end
  end

  # Socket

  defp open_socket(%{address: address, port: port}) do
    family = if tuple_size(address) == 4, do: [:inet], else: [:inet6, ipv6_v6only: true]
    open_socket(port, [:binary, ip: address, active: @active] ++ family, @bind_attempts)
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
    :counters.add(state.counters, Keyword.fetch!(@counters, name), 1)
    result
  end
end
