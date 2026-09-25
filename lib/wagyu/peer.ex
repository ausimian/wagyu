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
  # Initiating. A peer initiates when an outbound packet finds no usable
  # current key, or on `:wg_initiate`, a rekey, whether or not it has one. The
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
  #     `:current` goes. The peer then sends the packets it staged while it
  #     had no key, or, with none staged, a keepalive, an empty transport
  #     message. Either confirms the key to the responder.
  #   * A handshake this peer responded to becomes `:next`, replacing any
  #     earlier `:next`, and `:previous` goes, while `:current` stays the key
  #     to send with. The responder does not send under the new key until
  #     the initiator has: the first transport message that authenticates
  #     under `:next` promotes it to `:current`, and the old `:current`
  #     becomes `:previous`.
  #
  # A transport message authenticates under whichever slot holds its index,
  # so packets delayed under `:previous` still decrypt. A key pair that
  # leaves the slots is closed and its local index retired, which makes it a
  # tombstone; the ones in the slots when the peer exits go with the
  # process.
  #
  # Sending data. An outbound packet is sent under `:current` while that key
  # is less than REJECT_AFTER_TIME (180 seconds) old and below
  # REJECT_AFTER_MESSAGES. The plaintext is padded with zeros to a multiple
  # of 16 bytes, but never beyond the MTU, and its counter is the session's
  # next nonce, which Decibel never reuses. With no usable key the packet is
  # staged, within its own bound of 128 packets and 256 KiB, and the peer
  # initiates; staged packets go out in order under the next key it gets.
  # What does not fit is dropped and counted.
  #
  # Receiving data. A transport message is refused, before any cryptography,
  # when its key is past REJECT_AFTER_TIME or its counter is a duplicate or
  # older than the key's 8128-counter replay window. Only once it
  # authenticates does its counter enter the window. An empty plaintext is a
  # keepalive. Otherwise the plaintext must hold an IP packet no longer than
  # itself, which is trimmed to its IP length, from a source whose longest
  # AllowedIPs match is this peer. (The interface gives each peer only the
  # part of the table that decides that: `Wagyu.AllowedIPs.source_filter/2`.)
  # Such a packet goes to the link, admitted
  # against the link's own bound (`Wagyu.Link.deliver/2`); anything else is
  # counted and dropped. The source of a keepalive, or of a data packet that
  # passes those checks, becomes the endpoint, as the source of an
  # authenticated handshake message does.
  #
  # Nothing expires on a timer yet: an initiation whose response never comes
  # waits for the next outbound packet after REKEY_TIMEOUT to replace it,
  # and an expired key stays in its slot, unused, until a handshake displaces
  # it.
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

  alias Decibel.ReplayWindow
  alias Wagyu.Admission
  alias Wagyu.AllowedIPs
  alias Wagyu.Config
  alias Wagyu.Interface
  alias Wagyu.IP
  alias Wagyu.Link
  alias Wagyu.Noise
  alias Wagyu.Packet
  alias Wagyu.Packet.{Response, Transport}
  alias Wagyu.TAI64N

  # REKEY_TIMEOUT and REJECT_AFTER_TIME, in milliseconds.
  @rekey_timeout 5_000
  @reject_after_time 180_000
  # Counters a key pair remembers behind the highest it has accepted, as in
  # wireguard-go and Linux.
  @replay_window 8128
  # The longest a peer waits for the wall clock to reach its initiation's
  # timestamp: two TAI64N rounding steps, in nanoseconds.
  @max_timestamp_wait 2 * 0x1000000

  @slots [:next, :current, :previous]

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, args), do: GenServer.start_link(__MODULE__, {identity, args})

  @impl true
  def init({identity, %{root: root, peer: %Config.Peer{} = peer, socket: socket, counters: counters} = args}) do
    %{inbound: inbound, outbound: outbound, handoffs: handoffs, staging: staging, allowed_ips: allowed_ips} = args
    Process.flag(:sensitive, true)

    {:ok,
     %{
       root: root,
       public_key: peer.public_key,
       identity: identity,
       peer: peer,
       allowed_ips: allowed_ips,
       socket: socket,
       counters: counters,
       inbound: inbound,
       outbound: outbound,
       handoffs: handoffs,
       staging: staging,
       mac1_key: Packet.mac1_key(peer.public_key),
       endpoint: endpoint(peer.endpoint),
       initiation: nil,
       received: nil,
       handshake_sent_at: nil,
       next: nil,
       current: nil,
       previous: nil,
       staged: :queue.new(),
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

  def handle_info({:wg_outbound, packet}, state) do
    Admission.release(state.outbound, 1, byte_size(packet))
    {:noreply, send_packet(state, packet)}
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
  def format_status(status), do: Wagyu.Redact.format_status(status, [:identity, :peer, :staged])

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
        state = install_next(state, key_pair(session, index, remote_index, state.clock.()))
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
      :ok = wait_for(timestamp)
      initiation = %{session: session, local_index: index, timestamp: timestamp, sent_at: state.clock.()}
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
      {:ok, %Transport{} = transport} -> transport(state, index, transport, source)
      # Cookie replies wait for cookie support.
      _cookie_reply -> dropped(state)
    end
  end

  defp response(state, index, response, source) do
    with %{local_index: ^index, session: session, sent_at: sent_at} <- state.initiation,
         :ok <- Noise.read_response(session, response) do
      # The initiator's key is as old as its initiation, so it is never
      # younger than the responder's, which dates from the response: a
      # response that arrives too late yields a key already expired, and
      # the next packet starts a new handshake.
      key_pair = key_pair(session, index, response.sender_index, sent_at)

      %{state | initiation: nil, endpoint: source}
      |> install_current(key_pair)
      |> count(:responses_accepted)
      |> confirm_to_responder()
    else
      _unmatched_or_unauthenticated -> state |> count(:responses_invalid) |> dropped()
    end
  end

  # The replay window is checked before decryption, which is the expensive
  # part, and moves only once the message authenticates, so a forged counter
  # cannot close the window on genuine ones.
  defp transport(state, index, %Transport{counter: counter} = transport, source) do
    with {:key, {slot, key_pair}} <- {:key, slot(state, index)},
         {:fresh, true} <- {:fresh, fresh?(state, key_pair)},
         {:replay, :ok} <- {:replay, ReplayWindow.check(key_pair.replay, counter)},
         {:ok, plaintext} <- Noise.open(key_pair.session, transport) do
      state = Map.put(state, slot, %{key_pair | replay: ReplayWindow.commit(key_pair.replay, counter)})
      state = if slot == :next, do: confirm(state), else: state
      state = receive_plaintext(state, plaintext, source)
      # Staged packets go out only now, to the endpoint this message may
      # have just moved.
      if slot == :next, do: send_staged(state), else: state
    else
      {:fresh, false} -> state |> count(:transport_expired) |> dropped()
      {:replay, {:error, _duplicate_or_stale}} -> state |> count(:transport_replayed) |> dropped()
      _no_key_pair_or_unauthenticated -> state |> count(:transport_invalid) |> dropped()
    end
  end

  defp receive_plaintext(state, "", source), do: %{state | endpoint: source} |> count(:keepalives_received)

  defp receive_plaintext(state, plaintext, source) do
    with {:ip, {:ok, %{source: address, length: length}}} <- {:ip, IP.parse(plaintext)},
         {:allowed, true} <- {:allowed, AllowedIPs.allowed?(state.allowed_ips, address, state.public_key)} do
      state = %{state | endpoint: source}

      # The link counts a packet it refuses as an ingress drop.
      case Link.deliver(state.root, [binary_part(plaintext, 0, length)]) do
        0 -> count(state, :transport_received)
        _refused -> state
      end
    else
      {:ip, {:error, _reason}} -> state |> count(:transport_malformed) |> dropped()
      {:allowed, false} -> state |> count(:transport_source_denied) |> dropped()
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

  defp key_pair(session, local_index, remote_index, created_at) do
    %{
      session: session,
      local_index: local_index,
      remote_index: remote_index,
      created_at: created_at,
      replay: ReplayWindow.new(@replay_window)
    }
  end

  # REJECT_AFTER_TIME: no key sends or receives once it is this old.
  defp fresh?(state, key_pair), do: state.clock.() - key_pair.created_at < @reject_after_time

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

  # The initiator's first transport message under a new key confirms it:
  # staged data if there is any, and otherwise a keepalive.
  defp confirm_to_responder(%{current: key_pair} = state) do
    if :queue.is_empty(state.staged) do
      case Noise.seal(key_pair.session, key_pair.remote_index, "") do
        {:ok, frame} -> transmit(state, frame, :keepalives_sent)
        :error -> state
      end
    else
      send_staged(state)
    end
  end

  defp send_packet(state, packet) do
    with %{} = key_pair <- state.current,
         true <- fresh?(state, key_pair),
         {:ok, frame} <- Noise.seal(key_pair.session, key_pair.remote_index, pad(packet, state.identity.stack[:mtu])) do
      transmit(state, frame, :transport_sent)
    else
      # No key, one past REJECT_AFTER_TIME, or one that has sent
      # REJECT_AFTER_MESSAGES: the packet waits for a new handshake.
      _no_usable_key -> state |> stage(packet) |> initiate()
    end
  end

  # Zero padding to a multiple of 16 bytes, capped at the MTU.
  defp pad(packet, mtu) do
    size = byte_size(packet)
    padded = min(size + rem(16 - rem(size, 16), 16), mtu)
    if padded > size, do: [packet, <<0::size((padded - size) * 8)>>], else: packet
  end

  # Staged packets are admitted against `state.staging`, which the
  # interface holds too, so that it counts any still waiting when this
  # process exits as dropped.
  defp stage(state, packet) do
    case Admission.admit(state.staging, 1, byte_size(packet)) do
      :ok -> %{state | staged: :queue.in(packet, state.staged)}
      :full -> state |> count(:staged_dropped) |> Map.update!(:outbound_dropped, &(&1 + 1))
    end
  end

  # Sends the staged packets in order. If the key stops being usable part
  # way, the rest are staged again, still in order. Each stays admitted
  # until just before it is sent, and is released first so that it fits if
  # it is staged again, so if the peer dies part-way the interface counts
  # the unsent rest, missing at most the one being sent.
  defp send_staged(state) do
    state.staged
    |> :queue.to_list()
    |> Enum.reduce(%{state | staged: :queue.new()}, fn packet, state ->
      Admission.release(state.staging, 1, byte_size(packet))
      send_packet(state, packet)
    end)
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
