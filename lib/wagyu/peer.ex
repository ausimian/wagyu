defmodule Wagyu.Peer do
  @moduledoc false

  # One process per active configured peer, started by the interface when
  # outbound traffic or an authorized initiation first needs it. The same
  # process carries every handshake with its peer, so a rekey never starts
  # another.
  #
  # A peer owns its handshakes, its transport sessions and their key slots,
  # and its endpoint, and it sends its own datagrams on the interface's UDP
  # socket with `:gen_udp.send/4`. Every message sent here was admitted
  # against one of its bounds first: `{:wg_outbound, ip_packet}` against
  # `:outbound`, `{:wg_frame, local_index, frame, source}` against
  # `:inbound`, and the handoff against `:handoffs`, which counts messages
  # only. The peer releases each as it takes it off the mailbox.
  #
  # Responding. After the interface authorizes an initiation for this peer,
  # the handshake worker hands its responder session over with
  # `{:wg_handoff, ticket, metadata}`, where `metadata` holds the initiator's
  # sender index, the initiation's timestamp and its source. The peer
  # accepts the ticket, registers a local index with the interface, and
  # writes the response straight away: its sender index is the new local
  # index and its receiver index the initiator's sender index. The source
  # becomes the endpoint. An initiation no newer than the last one the peer
  # took, which a slow worker can deliver late, is closed instead, and a
  # ticket that cannot be accepted is dropped. Unlike wireguard-go, which
  # has room for one handshake per peer, responding does not abandon an
  # initiation of the peer's own in flight, so when both sides initiate at
  # once both handshakes complete and neither waits for a retry.
  #
  # Initiating. A peer initiates when an outbound packet finds no current
  # key, or on `:wg_initiate`, a rekey, whether or not it has one. The
  # interface allocates the initiation's sender index and timestamp
  # (`Wagyu.Interface.allocate_initiation/2`) before it is sent. The
  # timestamp is strictly greater than any the interface gave this peer
  # before, so it can be a little ahead of the wall clock, and the peer
  # waits for the clock to reach it before sending (at most two 2^24 ns
  # rounding steps, which is all that REKEY_TIMEOUT and a restart can add;
  # only a clock that steps back leads by more). A timestamp is therefore
  # never sent early, and a later interface's timestamps follow it. A new
  # initiation replaces any still in flight, whose session is closed and
  # whose index is retired, but no handshake message goes out within
  # REKEY_TIMEOUT (5 seconds) of the last one this peer sent, initiation or
  # response, as in wireguard-go. A peer with neither a configured nor a
  # learned endpoint cannot initiate, and counts `:initiations_no_endpoint`
  # instead. A response is taken only for the index of the initiation in
  # flight, and only once it authenticates; until then neither the key
  # slots nor the endpoint change. Its source then becomes the endpoint.
  #
  # Key slots. As in wireguard-go, a completed handshake is a key pair: its
  # transport session, its local index and the remote party's index. A peer
  # holds up to three, `:next`, `:current` and `:previous`, and sends only
  # with `:current`:
  #
  #   * A handshake this peer initiated becomes `:current` at once. The old
  #     `:current` becomes `:previous`, unless an unconfirmed `:next` is
  #     waiting, which is newer: then `:next` becomes `:previous` and the old
  #     `:current` goes. The peer then sends a keepalive, an empty transport
  #     message, which confirms the key to the responder. (Once there is a
  #     data path, queued data will do that instead.)
  #   * A handshake this peer responded to becomes `:next`, replacing any
  #     earlier `:next`, and `:previous` goes, while `:current` stays the key
  #     to send with. The responder does not send under the new key until
  #     the initiator has: the first transport message that authenticates
  #     under `:next` promotes it to `:current`, and the old `:current`
  #     becomes `:previous`.
  #
  # A transport message authenticates under whichever slot holds its index,
  # so packets delayed under `:previous` still decrypt. There is no replay
  # window, data path or roaming on transport yet, so authenticated data is
  # dropped. A key pair that leaves the slots is closed and its local index
  # retired, which makes it a tombstone; the ones in the slots when the peer
  # exits go with the process. Nothing expires on a timer yet: an initiation
  # whose response never comes waits for the next outbound packet after
  # REKEY_TIMEOUT to replace it, and keys stay until a handshake displaces
  # them.
  #
  # Handshake events are counted in the interface's shared counters. Frames
  # and packets the peer drops are counted in its own state.
  #
  # The peer owns Decibel sessions, whose state lives in the process
  # dictionary, so it is marked sensitive, and its status hides the local
  # key pair and the peer's preshared key.
  #
  # Time comes from `state.clock`, monotonic milliseconds, which tests
  # replace with a fake clock.

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Config
  alias Wagyu.Interface
  alias Wagyu.Noise
  alias Wagyu.Packet
  alias Wagyu.Packet.{Response, Transport}
  alias Wagyu.TAI64N

  # REKEY_TIMEOUT, in milliseconds.
  @rekey_timeout 5_000
  # The longest a peer waits for the wall clock to reach its initiation's
  # timestamp: two TAI64N rounding steps, in nanoseconds.
  @max_timestamp_wait 2 * 0x1000000

  @slots [:next, :current, :previous]

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, args), do: GenServer.start_link(__MODULE__, {identity, args})

  @impl true
  def init({identity, %{root: root, peer: %Config.Peer{} = peer, socket: socket, counters: counters} = args}) do
    %{inbound: inbound, outbound: outbound, handoffs: handoffs} = args
    Process.flag(:sensitive, true)

    {:ok,
     %{
       root: root,
       public_key: peer.public_key,
       identity: identity,
       peer: peer,
       socket: socket,
       counters: counters,
       inbound: inbound,
       outbound: outbound,
       handoffs: handoffs,
       mac1_key: Packet.mac1_key(peer.public_key),
       endpoint: endpoint(peer.endpoint),
       initiation: nil,
       received: nil,
       handshake_sent_at: nil,
       next: nil,
       current: nil,
       previous: nil,
       outbound_dropped: 0,
       inbound_dropped: 0,
       clock: fn -> System.monotonic_time(:millisecond) end
     }}
  end

  @impl true
  def handle_info({:wg_handoff, ticket, metadata}, state) do
    Admission.release(state.handoffs, 1, 0)
    {:noreply, accept_handshake(state, ticket, metadata)}
  end

  # There is no data path yet, so every outbound packet is dropped, but one
  # that finds no key to send with starts a handshake.
  def handle_info({:wg_outbound, packet}, state) do
    Admission.release(state.outbound, 1, byte_size(packet))
    state = %{state | outbound_dropped: state.outbound_dropped + 1}
    {:noreply, if(state.current, do: state, else: initiate(state))}
  end

  def handle_info({:wg_frame, index, frame, source}, state) do
    Admission.release(state.inbound, 1, byte_size(frame))
    {:noreply, receive_frame(state, index, frame, source)}
  end

  # A rekey: a new handshake, whether or not there is a current key. Nothing
  # sends this yet; rekey and retry timers will.
  def handle_info(:wg_initiate, state), do: {:noreply, initiate(state)}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def format_status(status), do: Wagyu.Redact.format_status(status, [:identity, :peer])

  # Responding

  defp accept_handshake(state, ticket, metadata) do
    with {:ok, session} <- accept(ticket),
         :ok <- newer(state.received, metadata, session),
         {:ok, index} <- allocate_index(state, session) do
      respond(state, session, index, metadata)
    else
      :error -> state
    end
  end

  # A ticket that has expired, or was already accepted, raises.
  defp accept(ticket) do
    {:ok, Decibel.accept_handoff(ticket)}
  rescue
    Decibel.HandoffError -> :error
  end

  defp newer(nil, _metadata, _session), do: :ok

  defp newer(received, metadata, session) do
    if TAI64N.after?(metadata.timestamp, received), do: :ok, else: close(session)
  end

  defp allocate_index(state, session) do
    case Interface.allocate_index(state.root, state.public_key) do
      {:ok, _index} = ok -> ok
      :error -> close(session)
    end
  end

  defp respond(state, session, index, %{sender_index: remote_index, timestamp: timestamp, source: source}) do
    case Noise.write_response(session, index, remote_index, state.mac1_key) do
      {:ok, frame} ->
        state = install_next(state, key_pair(session, index, remote_index))
        transmit(%{state | endpoint: source, received: timestamp}, frame, :responses_sent)

      :error ->
        :ok = Decibel.close(session)
        :ok = Interface.retire_index(state.root, index)
        state
    end
  end

  # Initiating

  defp initiate(%{endpoint: nil} = state), do: count(state, :initiations_no_endpoint)

  defp initiate(state) do
    with :ok <- due(state),
         {:ok, index, timestamp} <- Interface.allocate_initiation(state.root, state.public_key) do
      session = Noise.initiator(state.identity, state.public_key)
      frame = Noise.write_initiation(session, index, timestamp, state.mac1_key)
      initiation = %{session: session, local_index: index, timestamp: timestamp}
      :ok = wait_for(timestamp)
      transmit(%{discard_initiation(state) | initiation: initiation}, frame, :initiations_sent)
    else
      :error -> state
    end
  end

  defp due(%{handshake_sent_at: nil}), do: :ok

  defp due(state) do
    if state.clock.() - state.handshake_sent_at >= @rekey_timeout, do: :ok, else: :error
  end

  defp wait_for(timestamp) do
    {:ok, at} = TAI64N.to_unix(timestamp)

    case at - System.os_time(:nanosecond) do
      ahead when ahead > 0 and ahead <= @max_timestamp_wait -> Process.sleep(div(ahead, 1_000_000) + 1)
      _reached_or_clock_stepped_back -> :ok
    end
  end

  defp discard_initiation(%{initiation: nil} = state), do: state

  defp discard_initiation(%{initiation: initiation} = state) do
    :ok = Decibel.close(initiation.session)
    :ok = Interface.retire_index(state.root, initiation.local_index)
    %{state | initiation: nil}
  end

  # Inbound frames

  defp receive_frame(state, index, frame, source) do
    case Packet.decode(frame) do
      {:ok, %Response{} = response} -> response(state, index, response, source)
      {:ok, %Transport{} = transport} -> transport(state, index, transport)
      # Cookie replies wait for cookie support.
      _cookie_reply -> dropped(state)
    end
  end

  defp response(state, index, response, source) do
    with %{local_index: ^index, session: session} <- state.initiation,
         :ok <- Noise.read_response(session, response) do
      key_pair = key_pair(session, index, response.sender_index)

      %{state | initiation: nil, endpoint: source}
      |> install_current(key_pair)
      |> count(:responses_accepted)
      |> keepalive()
    else
      _unmatched_or_unauthenticated -> state |> count(:responses_invalid) |> dropped()
    end
  end

  defp transport(state, index, transport) do
    with {slot, key_pair} <- slot(state, index),
         {:ok, plaintext} <- Noise.open(key_pair.session, transport) do
      state = if slot == :next, do: confirm(state), else: state
      # A keepalive needs nothing more; data waits for the data path.
      if plaintext == "", do: state, else: dropped(state)
    else
      _no_key_pair_or_unauthenticated -> state |> count(:transport_invalid) |> dropped()
    end
  end

  defp slot(state, index) do
    Enum.find_value(@slots, fn slot ->
      case Map.fetch!(state, slot) do
        %{local_index: ^index} = key_pair -> {slot, key_pair}
        _other -> nil
      end
    end)
  end

  # Key slots

  defp key_pair(session, local_index, remote_index),
    do: %{session: session, local_index: local_index, remote_index: remote_index}

  defp install_next(state, key_pair), do: %{discard(state, [:next, :previous]) | next: key_pair}

  defp install_current(%{next: nil} = state, key_pair) do
    state = discard(state, [:previous])
    %{state | previous: state.current, current: key_pair}
  end

  defp install_current(state, key_pair) do
    state = discard(state, [:previous, :current])
    %{state | previous: state.next, next: nil, current: key_pair}
  end

  defp confirm(state) do
    state = discard(state, [:previous])
    count(%{state | previous: state.current, current: state.next, next: nil}, :keys_confirmed)
  end

  defp discard(state, slots) do
    Enum.reduce(slots, state, fn slot, state ->
      case Map.fetch!(state, slot) do
        nil ->
          state

        key_pair ->
          :ok = Decibel.close(key_pair.session)
          :ok = Interface.retire_index(state.root, key_pair.local_index)
          Map.put(state, slot, nil)
      end
    end)
  end

  # Sending

  defp keepalive(%{current: key_pair} = state) do
    case Noise.seal(key_pair.session, key_pair.remote_index, "") do
      {:ok, frame} -> transmit(state, frame, :keepalives_sent)
      :error -> state
    end
  end

  # A handshake message starts the REKEY_TIMEOUT wait whether or not the
  # send succeeds, so a failing socket is not retried for every packet.
  defp transmit(%{endpoint: {address, port}} = state, frame, event) do
    state =
      if event in [:initiations_sent, :responses_sent], do: %{state | handshake_sent_at: state.clock.()}, else: state

    case :gen_udp.send(state.socket, address, port, frame) do
      :ok -> count(state, event)
      {:error, _reason} -> count(state, :send_errors)
    end
  end

  defp endpoint(nil), do: nil
  defp endpoint(%{address: address, port: port}), do: {address, port}

  defp close(session) do
    :ok = Decibel.close(session)
    :error
  end

  defp count(state, name) do
    :ok = Interface.count_peer_event(state.counters, name)
    state
  end

  defp dropped(state), do: %{state | inbound_dropped: state.inbound_dropped + 1}
end
