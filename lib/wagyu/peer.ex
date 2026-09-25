defmodule Wagyu.Peer do
  @moduledoc false

  # One process per active configured peer, started by the interface when
  # outbound traffic or an authorized initiation first needs it, or when the
  # interface starts, for a peer with a persistent keepalive. The same
  # process carries every handshake with its peer, so neither a rekey nor a
  # retry ever starts another.
  #
  # A peer owns its handshakes, its transport sessions and their key slots,
  # its endpoint and its timers, and it sends its own datagrams on the
  # interface's UDP socket with `:gen_udp.send/4`. Every message sent here
  # was admitted against one of its bounds first: `{:wg_outbound,
  # ip_packet}` against `:outbound`, `{:wg_frame, local_index, frame,
  # source}` against `:inbound`, and the handoff against `:handoffs`, which
  # counts messages only. The peer releases each as it takes it off the
  # mailbox.
  #
  # Responding. After the interface authorizes an initiation for this peer,
  # the handshake worker hands its responder session, which has this peer's
  # preshared key, over with `{:wg_handoff, ticket, metadata}`, where
  # `metadata` holds the initiator's sender index, the initiation's
  # timestamp and its source. The peer
  # accepts the ticket, registers a local index with the interface, and
  # writes the response straight away: its sender index is the new local
  # index and its receiver index the initiator's sender index. The source
  # becomes the endpoint. An initiation no newer than the last one the peer
  # took, which a slow worker can deliver late, is closed instead, and a
  # ticket that cannot be accepted is dropped. A worker that claimed this
  # peer but has no session to hand over sends `:wg_handoff_abandoned`
  # instead, which releases its handoff. Unlike wireguard-go, which
  # has room for one handshake per peer, responding does not abandon an
  # initiation of the peer's own in flight, so when both sides initiate at
  # once both handshakes complete and neither waits for a retry.
  #
  # Initiating. A peer initiates when an outbound packet finds no usable
  # current key, and when one of the timers below calls for a rekey. The
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
  # Retrying. An initiation that gets no response is sent again, as a new
  # initiation, REKEY_TIMEOUT plus up to 333 ms of random jitter after the
  # last handshake message, for as long as the attempt lasts: REKEY_ATTEMPT_TIME
  # (90 seconds) from when it began. Only an outbound packet that has to
  # wait for a key extends the attempt, to 90 seconds from that packet; a
  # timer that calls for a handshake while one is already being attempted
  # joins it. An attempt ends when a handshake completes, as initiator or as
  # the responder whose key is confirmed. If it runs out instead, the
  # initiation is discarded and the packets waiting for a key are dropped
  # and counted.
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
  # so packets delayed under `:previous` still decrypt. A key pair leaves
  # its slot when a newer handshake displaces it or when it reaches
  # REJECT_AFTER_TIME, after which no packet under it can be accepted. It
  # is then closed and its local index retired, which makes it a tombstone;
  # the ones in the slots when the peer exits go with the process.
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
  # Timers. As in wireguard-go, with times from its constants:
  #
  #   * Rekey. A key this peer initiated is replaced once it is
  #     REKEY_AFTER_TIME (120 seconds) old, when the peer next sends under
  #     it, and any key once it has sent REKEY_AFTER_MESSAGES (2^60). A
  #     responder never initiates just because its key is old; its
  #     initiator does that. An initiator that receives under a key within
  #     KEEPALIVE_TIMEOUT plus REKEY_TIMEOUT of REJECT_AFTER_TIME (at 165
  #     seconds) initiates once more, in case it has nothing to send before
  #     the key expires.
  #   * Passive keepalive. KEEPALIVE_TIMEOUT (10 seconds) after data is
  #     received with nothing sent since, not even a handshake message, the
  #     peer sends a keepalive, so the other side knows its data arrived, or,
  #     if its key has expired since, initiates. Keepalives received and
  #     handshakes do not start this timer, so two idle peers stay quiet.
  #   * New handshake. KEEPALIVE_TIMEOUT plus REKEY_TIMEOUT (15 seconds),
  #     plus jitter, after data is sent with no authenticated packet
  #     received since, the peer initiates, since its key may be stale on
  #     the other side.
  #   * Persistent keepalive. With one configured, the peer sends a
  #     keepalive whenever that many seconds pass with no authenticated
  #     packet sent or received, and once when it starts. Without a usable
  #     key, it initiates instead.
  #   * Zeroing. REJECT_AFTER_TIME times three (540 seconds) after its last
  #     new key pair, or after an attempt that ran out when it has no such
  #     timer running, the peer discards every key, and, unless it is
  #     attempting a handshake, its initiation and staged packets too. A
  #     peer with no persistent keepalive that is not attempting a handshake
  #     then asks the interface to forget it (`Wagyu.Interface.release_peer/3`)
  #     and exits; the interface starts a new one when it is next needed,
  #     with the endpoint this one had.
  #
  # Each timer is a deadline on `state.clock` in `state.timers`, and one
  # process timer is armed for the earliest deadline. When a `{:wg_timer,
  # tag}` message arrives the peer runs every timer whose deadline has
  # passed, earliest first, then arms the process timer for the next.
  # Cancelling a timer deletes its deadline, so a message from a timer that
  # has since been cancelled or moved, or one that arrives early, finds
  # nothing due and does nothing. The deadlines live in the process, so
  # they go with it when it crashes, and the interface's supervisor stops
  # peers with the interface.
  #
  # Handshake events are counted in the interface's shared counters. Frames
  # and packets the peer drops are counted in its own state.
  #
  # The peer owns Decibel sessions, whose state lives in the process
  # dictionary, so it is marked sensitive, and its status hides the local
  # key pair and the peer's preshared key.
  #
  # Time comes from `state.clock`, monotonic milliseconds, which tests
  # replace with a fake clock. Wall-clock time is used only to wait for an
  # initiation's timestamp, so stepping the wall clock neither extends a
  # key's life nor delays a timer.

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

  # WireGuard's timer constants, in milliseconds.
  @rekey_timeout 5_000
  @keepalive_timeout 10_000
  @rekey_after_time 120_000
  @rekey_attempt_time 90_000
  @reject_after_time 180_000
  # When an initiator that is receiving initiates once more.
  @last_minute_rekey @reject_after_time - @keepalive_timeout - @rekey_timeout
  # How long keys are kept after the last new key pair.
  @zero_after @reject_after_time * 3
  # The most random jitter added to a retry or a new handshake.
  @max_jitter 333
  # REKEY_AFTER_MESSAGES: a key that has sent this many is replaced.
  @rekey_after_messages 0x1000000000000000
  # Counters a key pair remembers behind the highest it has accepted, as in
  # wireguard-go and Linux.
  @replay_window 8128
  # The longest a peer waits for the wall clock to reach its initiation's
  # timestamp: two TAI64N rounding steps, in nanoseconds.
  @max_timestamp_wait 2 * 0x1000000

  @slots [:next, :current, :previous]
  # The order in which timers due at the same moment run: an attempt that
  # runs out is not retried, and keys are zeroed only after the rest.
  @timers [:give_up, :retry, :new_handshake, :keepalive, :persistent_keepalive, :zero]

  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, args), do: GenServer.start_link(__MODULE__, {identity, args})

  @impl true
  def init({identity, %{root: root, peer: %Config.Peer{} = peer, socket: socket, counters: counters} = args}) do
    %{inbound: inbound, outbound: outbound, handoffs: handoffs, staging: staging, allowed_ips: allowed_ips} = args
    Process.flag(:sensitive, true)
    clock = fn -> System.monotonic_time(:millisecond) end

    state = %{
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
      endpoint: Map.get(args, :endpoint) || endpoint(peer.endpoint),
      initiation: nil,
      received: nil,
      handshake_sent_at: nil,
      next: nil,
      current: nil,
      previous: nil,
      staged: :queue.new(),
      outbound_dropped: 0,
      inbound_dropped: 0,
      persistent_keepalive: peer.persistent_keepalive * 1_000,
      last_minute_rekey: false,
      timers: %{},
      timer: nil,
      clock: clock
    }

    # A persistent keepalive goes out as soon as the peer starts.
    state = if state.persistent_keepalive > 0, do: set_timer(state, :persistent_keepalive, clock.()), else: state
    {:ok, arm(state)}
  end

  @impl true
  def handle_info({:wg_handoff, ticket, metadata}, state) do
    Admission.release(state.handoffs, 1, 0)
    {:noreply, state |> accept_handshake(ticket, metadata) |> arm()}
  end

  def handle_info(:wg_handoff_abandoned, state) do
    Admission.release(state.handoffs, 1, 0)
    {:noreply, state}
  end

  def handle_info({:wg_outbound, packet}, state) do
    Admission.release(state.outbound, 1, byte_size(packet))
    {:noreply, state |> send_packet(packet) |> arm()}
  end

  def handle_info({:wg_frame, index, frame, source}, state) do
    Admission.release(state.inbound, 1, byte_size(frame))
    {:noreply, state |> receive_frame(index, frame, source) |> arm()}
  end

  # The armed process timer, or one that has been replaced since. Either
  # way only the timers already due run.
  def handle_info({:wg_timer, tag}, state) do
    state = if match?({^tag, _ref, _deadline}, state.timer), do: %{state | timer: nil}, else: state

    case run_timers(state) do
      {:stop, state} -> {:stop, :normal, state}
      state -> {:noreply, arm(state)}
    end
  end

  # A rekey, as the timers start. Tests send it to rekey without waiting.
  def handle_info(:wg_initiate, state), do: {:noreply, state |> initiate(:rekey) |> arm()}

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
        state =
          state
          |> received_authenticated()
          |> install_next(key_pair(session, index, remote_index, state.clock.(), false))
          |> new_key_pair()

        transmit(%{state | endpoint: source, received: timestamp}, frame, :responses_sent)

      :error ->
        :ok = Decibel.close(session)
        :ok = Interface.retire_index(state.root, index)
        state
    end
  end

  # Initiating

  # `trigger` is `:demand` for an outbound packet that has to wait for a
  # key, which begins or extends the attempt, `:retry` for the retry timer,
  # and `:rekey` for anything else, which joins an attempt already under
  # way. While a retry is pending, it sends the next initiation.
  defp initiate(%{endpoint: nil} = state, _trigger), do: count(state, :initiations_no_endpoint)

  defp initiate(state, trigger) do
    now = state.clock.()

    state =
      if trigger == :demand or not pending?(state, :give_up),
        do: set_timer(state, :give_up, now + @rekey_attempt_time),
        else: state

    cond do
      trigger != :retry and pending?(state, :retry) -> state
      due?(state, now) -> send_initiation(state)
      true -> set_timer(state, :retry, state.handshake_sent_at + @rekey_timeout + jitter())
    end
  end

  defp send_initiation(state) do
    case Interface.allocate_initiation(state.root, state.public_key) do
      {:ok, index, timestamp} ->
        session = Noise.initiator(state.identity, state.public_key, state.peer.preshared_key)
        frame = Noise.write_initiation(session, index, timestamp, state.mac1_key)
        :ok = wait_for(timestamp)
        initiation = %{session: session, local_index: index, timestamp: timestamp, sent_at: state.clock.()}
        state = transmit(%{discard_initiation(state) | initiation: initiation}, frame, :initiations_sent)
        set_timer(state, :retry, state.handshake_sent_at + @rekey_timeout + jitter())

      :error ->
        state
    end
  end

  defp due?(%{handshake_sent_at: nil}, _now), do: true
  defp due?(state, now), do: now - state.handshake_sent_at >= @rekey_timeout

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
      key_pair = key_pair(session, index, response.sender_index, sent_at, true)

      %{state | initiation: nil, endpoint: source}
      |> received_authenticated()
      |> install_current(key_pair)
      |> new_key_pair()
      |> handshake_complete()
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
      state = received_authenticated(state)
      state = if slot == :next, do: state |> confirm() |> handshake_complete(), else: state
      state = receive_plaintext(state, plaintext, source)
      # Staged packets go out only now, to the endpoint this message may
      # have just moved.
      state = if slot == :next, do: send_staged(state), else: state
      last_minute_rekey(state)
    else
      {:fresh, false} -> state |> count(:transport_expired) |> dropped()
      {:replay, {:error, _duplicate_or_stale}} -> state |> count(:transport_replayed) |> dropped()
      _no_key_pair_or_unauthenticated -> state |> count(:transport_invalid) |> dropped()
    end
  end

  defp receive_plaintext(state, "", source), do: %{state | endpoint: source} |> count(:keepalives_received)

  defp receive_plaintext(state, plaintext, source) do
    state = received_data(state)

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

  # An initiator still receiving under a key close to REJECT_AFTER_TIME
  # starts one handshake, in case it sends nothing that would.
  defp last_minute_rekey(%{last_minute_rekey: false, current: %{initiator: true} = key_pair} = state) do
    if state.clock.() - key_pair.created_at >= @last_minute_rekey,
      do: initiate(%{state | last_minute_rekey: true}, :rekey),
      else: state
  end

  defp last_minute_rekey(state), do: state

  defp slot(state, index) do
    Enum.find_value(@slots, fn slot ->
      case Map.fetch!(state, slot) do
        %{local_index: ^index} = key_pair -> {slot, key_pair}
        _other -> nil
      end
    end)
  end

  # Key slots

  defp key_pair(session, local_index, remote_index, created_at, initiator) do
    %{
      session: session,
      local_index: local_index,
      remote_index: remote_index,
      created_at: created_at,
      initiator: initiator,
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

  # Key pairs past REJECT_AFTER_TIME can accept nothing more.
  defp discard_expired(state), do: discard(state, Enum.filter(@slots, &expired?(state, &1)))

  defp expired?(state, slot) do
    case Map.fetch!(state, slot) do
      nil -> false
      key_pair -> not fresh?(state, key_pair)
    end
  end

  # Sending

  # The initiator's first transport message under a new key confirms it:
  # staged data if there is any, and otherwise a keepalive.
  defp confirm_to_responder(state) do
    if :queue.is_empty(state.staged), do: send_keepalive(state), else: send_staged(state)
  end

  # `demand` is false for a packet that was already waiting for a key, so
  # staging it again does not extend the handshake attempt, and neither
  # does a packet dropped because the staging queue is full.
  defp send_packet(state, packet, demand \\ true) do
    with %{} = key_pair <- usable(state),
         {:ok, frame} <- Noise.seal(key_pair.session, key_pair.remote_index, pad(packet, state.identity.stack[:mtu])) do
      state |> transmit(frame, :transport_sent) |> rekey_after_sending(key_pair)
    else
      # No key, one past REJECT_AFTER_TIME, or one that has sent
      # REJECT_AFTER_MESSAGES: the packet waits for a new handshake.
      _no_usable_key -> stage_and_initiate(state, packet, demand)
    end
  end

  defp stage_and_initiate(state, packet, demand) do
    case stage(state, packet) do
      {:staged, state} when demand -> initiate(state, :demand)
      {_staged_or_dropped, state} -> initiate(state, :rekey)
    end
  end

  # A keepalive, an empty transport message, when there is a usable key.
  defp send_keepalive(state) do
    with %{} = key_pair <- usable(state),
         {:ok, frame} <- Noise.seal(key_pair.session, key_pair.remote_index, "") do
      state |> transmit(frame, :keepalives_sent) |> rekey_after_sending(key_pair)
    else
      _no_usable_key -> state
    end
  end

  # The current key pair while it is younger than REJECT_AFTER_TIME, or nil.
  defp usable(%{current: key_pair} = state) do
    if key_pair && fresh?(state, key_pair), do: key_pair
  end

  # REKEY_AFTER_MESSAGES for any key, and REKEY_AFTER_TIME for a key this
  # peer initiated.
  defp rekey_after_sending(state, key_pair) do
    if Decibel.nonce(key_pair.session, :out) >= @rekey_after_messages or
         (key_pair.initiator and state.clock.() - key_pair.created_at >= @rekey_after_time),
       do: initiate(state, :rekey),
       else: state
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
      :ok -> {:staged, %{state | staged: :queue.in(packet, state.staged)}}
      :full -> {:dropped, state |> count(:staged_dropped) |> Map.update!(:outbound_dropped, &(&1 + 1))}
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
      send_packet(state, packet, false)
    end)
  end

  # Drops every staged packet, counting each.
  defp drop_staged(state) do
    packets = :queue.to_list(state.staged)
    Admission.release(state.staging, length(packets), Admission.bytes(packets))

    %{state | staged: :queue.new()}
    |> count(:staged_dropped, length(packets))
    |> Map.update!(:outbound_dropped, &(&1 + length(packets)))
  end

  # A handshake message starts the REKEY_TIMEOUT wait whether or not the
  # send succeeds, so a failing socket is not retried for every packet.
  defp transmit(%{endpoint: {address, port}} = state, frame, event) do
    state = sent_authenticated(state, event)

    case :gen_udp.send(state.socket, address, port, frame) do
      :ok -> count(state, event)
      {:error, _reason} -> count(state, :send_errors)
    end
  end

  # Timer events

  defp sent_authenticated(state, event) when event in [:initiations_sent, :responses_sent],
    do: %{state | handshake_sent_at: state.clock.()} |> cancel_timer(:keepalive) |> persistent_keepalive()

  defp sent_authenticated(state, event) do
    state = state |> cancel_timer(:keepalive) |> persistent_keepalive()

    if event == :transport_sent,
      do:
        set_timer_unless_pending(state, :new_handshake, state.clock.() + @keepalive_timeout + @rekey_timeout + jitter()),
      else: state
  end

  defp received_authenticated(state), do: state |> cancel_timer(:new_handshake) |> persistent_keepalive()

  defp received_data(state), do: set_timer_unless_pending(state, :keepalive, state.clock.() + @keepalive_timeout)

  defp new_key_pair(state), do: %{set_timer(state, :zero, state.clock.() + @zero_after) | last_minute_rekey: false}

  defp handshake_complete(state), do: state |> cancel_timer(:retry) |> cancel_timer(:give_up)

  defp persistent_keepalive(%{persistent_keepalive: 0} = state), do: state

  defp persistent_keepalive(state),
    do: set_timer(state, :persistent_keepalive, state.clock.() + state.persistent_keepalive)

  # Timers

  # Runs the timers that are due, earliest first, until none is. Each is
  # deleted before it runs, and may set or cancel others. Key pairs past
  # REJECT_AFTER_TIME go first, so no timer sends under one.
  defp run_timers(state) do
    state = discard_expired(state)
    now = state.clock.()

    due =
      state.timers
      |> Enum.filter(fn {_name, deadline} -> deadline <= now end)
      |> Enum.min_by(fn {name, deadline} -> {deadline, Enum.find_index(@timers, &(&1 == name))} end, fn -> nil end)

    case due do
      nil ->
        state

      {name, _deadline} ->
        case fire(name, cancel_timer(state, name)) do
          {:stop, state} -> {:stop, state}
          state -> run_timers(state)
        end
    end
  end

  defp fire(:retry, state), do: initiate(state, :retry)

  defp fire(:give_up, state) do
    state
    |> cancel_timer(:retry)
    |> discard_initiation()
    |> drop_staged()
    |> count(:handshakes_abandoned)
    |> set_timer_unless_pending(:zero, state.clock.() + @zero_after)
  end

  # A key that has expired since the data arrived calls for a handshake.
  defp fire(:keepalive, state), do: if(usable(state), do: send_keepalive(state), else: initiate(state, :rekey))

  defp fire(:new_handshake, state), do: initiate(state, :rekey)

  defp fire(:persistent_keepalive, state) do
    state = persistent_keepalive(state)
    if usable(state), do: send_keepalive(state), else: initiate(state, :rekey)
  end

  defp fire(:zero, state) do
    state = state |> discard(@slots) |> cancel_timer(:keepalive) |> cancel_timer(:new_handshake)

    cond do
      pending?(state, :give_up) -> state
      state.persistent_keepalive > 0 -> state |> discard_initiation() |> drop_staged()
      true -> state |> discard_initiation() |> drop_staged() |> exit_if_idle()
    end
  end

  # The interface refuses while it has messages admitted for this process,
  # which then arrive and are handled first; the peer asks again later.
  defp exit_if_idle(state) do
    case Interface.release_peer(state.root, state.public_key, state.endpoint) do
      :ok -> {:stop, state}
      :busy -> set_timer(state, :zero, state.clock.() + @rekey_timeout)
    end
  end

  defp pending?(state, name), do: Map.has_key?(state.timers, name)

  defp set_timer(state, name, deadline), do: %{state | timers: Map.put(state.timers, name, deadline)}

  defp set_timer_unless_pending(state, name, deadline),
    do: if(pending?(state, name), do: state, else: set_timer(state, name, deadline))

  defp cancel_timer(state, name), do: %{state | timers: Map.delete(state.timers, name)}

  # Up to 333 ms, as in wireguard-go.
  defp jitter, do: :rand.uniform(@max_jitter + 1) - 1

  # Arms the process timer for the earliest deadline, including when each
  # key pair expires, unless one is already armed for no later. A timer
  # armed for later is cancelled; one that fires early finds nothing due
  # and arms the next.
  defp arm(state) do
    expiries = for slot <- @slots, key_pair = Map.fetch!(state, slot), do: key_pair.created_at + @reject_after_time

    case {Enum.min(Map.values(state.timers) ++ expiries, fn -> nil end), state.timer} do
      {nil, _timer} ->
        state

      {deadline, {_tag, _ref, armed}} when armed <= deadline ->
        state

      {deadline, timer} ->
        with {_tag, ref, _armed} <- timer, do: Process.cancel_timer(ref, async: true, info: false)
        tag = make_ref()
        ref = Process.send_after(self(), {:wg_timer, tag}, max(deadline - state.clock.(), 0))
        %{state | timer: {tag, ref, deadline}}
    end
  end

  defp endpoint(nil), do: nil
  defp endpoint(%{address: address, port: port}), do: {address, port}

  defp close(session) do
    :ok = Decibel.close(session)
    :error
  end

  defp count(state, name, increment \\ 1) do
    :ok = Interface.count_peer_event(state.counters, name, increment)
    state
  end

  defp dropped(state), do: %{state | inbound_dropped: state.inbound_dropped + 1}
end
