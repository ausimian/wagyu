defmodule Wagyu.Peer do
  @moduledoc false

  # Each active configured peer has one process. The interface starts it
  # when outbound traffic or an authorized initiation first needs it. For a
  # peer with a persistent keepalive, the interface starts it when the
  # interface starts. The same process carries every handshake with its
  # peer, so a rekey or a retry never starts a second process.
  #
  # A peer owns its handshakes, its key slots, its endpoint and its timers.
  # It has three helper processes. The four processes are the children of
  # one `Wagyu.Peer.Group`, and they start and stop together:
  #
  #   * The sealer (`Wagyu.Peer.Sealer`) takes the outbound packets from the
  #     interface, and seals them under the outbound half of the `:current`
  #     key pair. It also holds the packets that wait for a key.
  #   * The opener (`Wagyu.Peer.Opener`) takes the transport messages from
  #     the interface, opens them under the inbound half of each key pair,
  #     and gives the packets to the link.
  #   * The sender (`Wagyu.Peer.Sender`) writes the datagrams of the sealer
  #     and the handshake messages of the peer to the interface's UDP socket.
  #
  # Thus sealing, opening and the UDP send each have a process. The peer
  # holds no transport key: when a handshake completes, it moves both
  # directions of the session to the sealer and the opener
  # (`Decibel.split/2`). Each message to a peer, its sealer or its opener is
  # admitted against one of the peer's bounds first:
  #
  #   * `{:wg_outbound, ip_packets}` to the sealer, against `:outbound`. A
  #     batch is admitted packet by packet.
  #   * `{:wg_frame, local_index, frame, source}` against `:inbound`. A
  #     transport message goes to the opener. A response or a cookie reply
  #     goes to the peer.
  #   * The handoff against `:handoffs`, which counts messages only.
  #
  # Each message is released from its bound at a specific time:
  #
  #   * A handoff, when the peer takes it off the mailbox.
  #   * An outbound packet, when the sender sends it, or after the sealer
  #     admits it to the staging bound.
  #   * A frame, when the peer or the opener is done with it. For a data
  #     packet, this is after the packet goes to the link.
  #
  # After the sealer or the sender releases outbound packets, it tells the
  # interface (`Wagyu.Interface.outbound_taken/3`). The interface then frees
  # the link's egress credit for the packets that the queue no longer holds.
  #
  # Responding. After the interface authorizes an initiation for this peer,
  # the handshake worker hands over its responder session with
  # `{:wg_handoff, ticket, metadata}`. The session has this peer's
  # preshared key. `metadata` holds the initiator's sender index, the
  # timestamp of the initiation and its source.
  #
  # The peer accepts the ticket, registers a local index with the interface
  # and writes the response immediately. The sender index of the response
  # is the new local index. Its receiver index is the initiator's sender
  # index. The source becomes the endpoint.
  #
  # The peer does not take every handoff:
  #
  #   * A slow worker can deliver an initiation late. If the initiation is
  #     not newer than the last one that the peer took, the peer closes its
  #     session instead.
  #   * The peer drops a ticket that it cannot accept.
  #   * A worker that claimed this peer but has no session to hand over
  #     sends `:wg_handoff_abandoned` instead. This message releases the
  #     worker's handoff.
  #
  # Unlike wireguard-go, which has space for one handshake per peer, this
  # peer keeps its own initiation in flight when it responds. Thus, when
  # both sides initiate at the same time, both handshakes complete and
  # neither side waits for a retry.
  #
  # Initiating. A peer initiates when an outbound packet finds no usable
  # current key. It also initiates when one of the timers below calls for a
  # rekey. Before the peer sends an initiation, the interface allocates its
  # sender index and timestamp (`Wagyu.Interface.allocate_initiation/2`).
  #
  # The timestamp is always greater than any timestamp that the interface
  # gave this peer before. Thus it can be a little ahead of the wall clock.
  # The peer waits for the clock to reach the timestamp before it sends.
  # This wait is at most two 2^24 ns rounding steps, which is all that
  # REKEY_TIMEOUT and a restart can add. Only a clock that steps back can
  # make the lead larger. Thus the peer never sends a timestamp early, and
  # the timestamps of a later interface follow it.
  #
  # A new initiation replaces any initiation that is still in flight. The
  # peer closes the session of the old initiation and retires its index.
  # But no handshake message goes out within REKEY_TIMEOUT (5 seconds) of
  # the last initiation or response that this peer sent, as in wireguard-go.
  # A peer with no configured or learned endpoint cannot initiate. It
  # counts the initiation in `:initiations_no_endpoint` instead.
  #
  # The peer takes a response only for the index of the initiation in
  # flight, and only after the response authenticates. Until then, the key
  # slots and the endpoint do not change. After that, the source of the
  # response becomes the endpoint.
  #
  # Retrying. If an initiation gets no response, the peer sends a new
  # initiation. It sends it REKEY_TIMEOUT plus up to 333 ms of random jitter
  # after the last handshake message. The retries continue for the duration
  # of the attempt: REKEY_ATTEMPT_TIME (90 seconds) from its start. Only an
  # outbound packet that must wait for a key extends the attempt, to 90
  # seconds from that packet. A timer that calls for a handshake during an
  # attempt joins that attempt.
  #
  # An attempt ends when a handshake completes. This peer can be the
  # initiator, or the responder after the initiator confirms the key. If the
  # attempt runs out first, the peer discards the initiation. It drops the
  # packets that wait for a key, and counts them. It drops only the packets
  # that the sealer reported before: a packet that the sealer staged after
  # its last report stays, and its report starts a new attempt.
  #
  # Cookies. When a remote party is under load, it answers a handshake
  # message that has no valid MAC2 with a cookie reply. The reply goes to
  # the sender index of the message, which belongs to this peer. The peer
  # takes a reply only if it decrypts with the MAC1 of the last initiation
  # or response that the peer sent. As in Linux, the peer takes only one
  # reply for that message. For 120 seconds after the reply arrives, the
  # peer keys MAC2 on its handshake messages with the cookie.
  #
  # A reply does not make the peer send sooner. The next initiation goes
  # out on the retry timer, as in wireguard-go.
  #
  # Key slots. As in wireguard-go, a completed handshake gives a key pair:
  # its transport session, its local index and the remote party's index. A
  # peer holds up to three key pairs, in the slots `:next`, `:current` and
  # `:previous`. It sends only with `:current`.
  #
  #   * A handshake that this peer initiated becomes `:current` immediately.
  #     Usually the old `:current` becomes `:previous`. If a newer,
  #     unconfirmed `:next` waits, `:next` becomes `:previous` and the old
  #     `:current` leaves the slots. The sealer then sends the packets that
  #     it staged while it had no key. If it staged none, it sends a
  #     keepalive, which is an empty transport message. Each of these
  #     confirms the key to the responder.
  #   * A handshake that this peer responded to becomes `:next`. It replaces
  #     any earlier `:next`, and `:previous` leaves the slots. `:current`
  #     stays the key that the sealer sends with. The sealer holds the
  #     outbound half of `:next`, but does not send under it until the
  #     initiator sends under it. The first transport message that
  #     authenticates under `:next` promotes it to `:current`, and the old
  #     `:current` becomes `:previous`. The opener reports this message, and
  #     the peer then tells the sealer (`{:wg_promote, local_index}`).
  #
  # A transport message authenticates under the key pair that holds its
  # index, so packets that were delayed under `:previous` still decrypt. A
  # key pair leaves its slot when a newer handshake displaces it, or when it
  # reaches REJECT_AFTER_TIME. After REJECT_AFTER_TIME, the opener accepts
  # no packet under it. The peer then tells the sealer and the opener to
  # close their halves (`{:wg_discard, local_index}`), and retires its local
  # index, which makes it a tombstone. The halves of the key pairs that are
  # in the slots when the peer exits go with the group.
  #
  # Sending data. The sealer sends an outbound packet under `:current`
  # while that key is less than REJECT_AFTER_TIME (180 seconds) old and
  # below REJECT_AFTER_MESSAGES. It pads the plaintext with zeros to a
  # multiple of 16 bytes, but never past the MTU. The packet's counter is
  # the session's next nonce, which Decibel never uses again.
  #
  # If there is no usable key, the sealer stages the packet and the peer
  # initiates. Staged packets have their own bound of 128 packets and 256
  # KiB. The sealer sends staged packets in order under the next key that
  # it gets. It drops and counts the packets that do not fit. The sealer
  # reports its sends and its need for a handshake to the peer once for
  # each message that it takes (`{:wg_sealed, events, trigger, index,
  # number}`).
  #
  # Receiving data. The opener checks, opens and delivers the transport
  # messages (`Wagyu.Peer.Opener`). It reports what it received to the peer
  # (`{:wg_opened, events, source, confirmed, configured}`). The source of
  # a keepalive, or of a data packet that passes the checks of the opener,
  # becomes the endpoint, unless the interface admitted it before the
  # latest configure message. The source of an authenticated handshake
  # message also becomes the endpoint.
  #
  # Batching. The interface sends a peer's sealer its part of each egress
  # batch as one message. The sealer sends the batch under one key at one
  # moment, and reports it to the peer one time. The opener reports each
  # batch of packets that it gives to the link one time. Thus the peer
  # updates and arms the timers one time for each batch.
  #
  # Timers. These timers are as in wireguard-go, with times from its
  # constants:
  #
  #   * Rekey. The peer replaces a key that it initiated when the key is
  #     REKEY_AFTER_TIME (120 seconds) old and the peer next sends under it.
  #     It replaces any key after the key sends REKEY_AFTER_MESSAGES (2^60).
  #     A responder never initiates only because its key is old; its
  #     initiator does that. An initiator that receives under a key 165
  #     seconds old or older initiates one more time. This is necessary
  #     because possibly it has nothing to send before the key expires. 165
  #     seconds is REJECT_AFTER_TIME less KEEPALIVE_TIMEOUT and
  #     REKEY_TIMEOUT.
  #   * Passive keepalive. The peer sends a keepalive KEEPALIVE_TIMEOUT (10
  #     seconds) after it receives data, if it sent nothing after that, not
  #     even a handshake message. The keepalive tells the other side that
  #     its data arrived. If the key expired in that time, the peer
  #     initiates instead. Received keepalives and handshakes do not start
  #     this timer, so two idle peers stay quiet.
  #   * New handshake. The peer initiates KEEPALIVE_TIMEOUT plus
  #     REKEY_TIMEOUT (15 seconds), plus jitter, after it sends data, if it
  #     received no authenticated packet after that. The cause is that its
  #     key can be stale on the other side.
  #   * Persistent keepalive. If one is configured, the peer sends a
  #     keepalive when that number of seconds passes with no authenticated
  #     packet sent or received. It also sends one when it starts. If it has
  #     no usable key, it initiates instead.
  #   * Zeroing. The peer discards every key REJECT_AFTER_TIME times three
  #     (540 seconds) after its last new key pair. If no such timer runs
  #     when an attempt runs out, the peer discards every key 540 seconds
  #     after that. If the peer does not attempt a handshake at that time,
  #     it also discards its initiation and staged packets. Then, a peer
  #     with no persistent keepalive and no handshake attempt asks the
  #     interface to forget it (`Wagyu.Interface.release_peer/2`) and exits.
  #     The interface starts a new peer when it next needs one, with the
  #     endpoint that this peer had.
  #
  # Each timer is a deadline on `state.clock` in `state.timers`. The peer
  # arms one process timer for the earliest deadline. When a `{:wg_timer,
  # tag}` message arrives, the peer runs every timer whose deadline is in
  # the past, earliest first. It then arms the process timer for the next
  # deadline. To cancel a timer, the peer deletes its deadline. Thus a
  # message from a cancelled or moved timer, or an early message, finds
  # nothing due and does nothing.
  #
  # The deadlines are in the process, so they go with the process when it
  # crashes. The interface's supervisor stops peers with the interface.
  #
  # Endpoint. Each time the endpoint changes, the peer tells the interface
  # (`Wagyu.Interface.endpoint_learned/4`). The interface starts the next
  # process of the key with the last endpoint. Thus the endpoint stays when
  # the process exits.
  #
  # Configuration. When the peer set of the interface changes, the peer can
  # get `{:wg_configure, peer}`. The message has the new configuration of
  # this peer. The peer keeps its key pairs, replay windows, timers and
  # staged packets:
  #
  #   * New handshakes use the new preshared key. The key pairs that the
  #     peer has stay valid until they expire.
  #   * A new endpoint that is not `nil` replaces the current endpoint. A
  #     change to `nil` keeps the current endpoint.
  #   * A new persistent keepalive arms its timer again with the new
  #     interval. A change to 0 cancels the timer.
  #
  # The interface sends a new source filter to the opener itself.
  #
  # The peer counts the configure messages that it takes, and reports this
  # count with each endpoint. Thus the interface can ignore an endpoint that
  # the peer learned before it took the latest configuration. After each
  # configure message, the peer reports its current endpoint again.
  #
  # The peer counts handshake events in the interface's shared counters. It
  # counts the frames and packets that it drops in its own state.
  #
  # The peer owns the Decibel sessions of its handshakes, and their state is
  # in the process dictionary. Thus the process is marked sensitive. Its
  # status hides the local key pair and the peer's preshared key.
  #
  # Time comes from `state.clock`, in monotonic milliseconds. Tests replace
  # it with a fake clock. The peer uses wall-clock time only to wait for
  # the timestamp of an initiation. Thus a step in the wall clock does not
  # extend the life of a key or delay a timer.

  use GenServer, restart: :temporary

  alias Wagyu.Admission
  alias Wagyu.Config
  alias Wagyu.Cookie
  alias Wagyu.Interface
  alias Wagyu.Noise
  alias Wagyu.Packet
  alias Wagyu.Packet.{CookieReply, Response}
  alias Wagyu.Peer.Sealer
  alias Wagyu.TAI64N

  # WireGuard's timer constants, in milliseconds.
  @rekey_timeout 5_000
  @keepalive_timeout 10_000
  @rekey_attempt_time 90_000
  @reject_after_time 180_000
  # The key age at which an initiator that receives under the key initiates
  # one more time.
  @last_minute_rekey @reject_after_time - @keepalive_timeout - @rekey_timeout
  # How long keys are kept after the last new key pair.
  @zero_after @reject_after_time * 3
  # The maximum random jitter that the peer adds to a retry or a new
  # handshake.
  @max_jitter 333
  # The maximum time that a peer waits for the wall clock to reach the
  # timestamp of its initiation: two TAI64N rounding steps, in nanoseconds.
  @max_timestamp_wait 2 * 0x1000000
  # How long a cookie keys MAC2 after it arrives (COOKIE_REFRESH_TIME).
  @cookie_lifetime 120_000

  @slots [:next, :current, :previous]
  # The order in which timers that are due at the same moment run. An
  # attempt that runs out is not retried, and the peer zeroes keys only
  # after the other timers.
  @timers [:give_up, :retry, :new_handshake, :keepalive, :persistent_keepalive, :zero]

  # `Wagyu.Peer.Group` starts the peer after its sender, its sealer and its
  # opener, and gives it their pids in `args`.
  @spec start_link(Config.t(), map()) :: GenServer.on_start()
  def start_link(%Config{} = identity, args), do: GenServer.start_link(__MODULE__, {identity, args})

  @impl true
  def init({identity, %{root: root, peer: %Config.Peer{} = peer, counters: counters} = args}) do
    %{inbound: inbound, handoffs: handoffs, sender: sender, sealer: sealer, opener: opener} = args
    Process.flag(:sensitive, true)

    # The sealer and the opener report to the peer. They take no other
    # message before they know the peer.
    send(sealer, {:wg_owner, self()})
    send(opener, {:wg_owner, self()})

    clock = fn -> System.monotonic_time(:millisecond) end

    state = %{
      root: root,
      public_key: peer.public_key,
      identity: identity,
      peer: peer,
      sender: sender,
      sealer: sealer,
      opener: opener,
      counters: counters,
      inbound: inbound,
      handoffs: handoffs,
      mac1_key: Packet.mac1_key(peer.public_key),
      cookie_key: Cookie.key(peer.public_key),
      cookie: nil,
      last_mac1: nil,
      endpoint: Map.get(args, :endpoint) || endpoint(peer.endpoint),
      initiation: nil,
      received: nil,
      handshake_sent_at: nil,
      next: nil,
      current: nil,
      previous: nil,
      # The sequence number of the last packet that the sealer staged, as
      # its last report gave it. The peer drops staged packets only up to
      # this number.
      staged_seen: 0,
      inbound_dropped: 0,
      persistent_keepalive: peer.persistent_keepalive * 1_000,
      configured: 0,
      last_minute_rekey: false,
      timers: %{},
      timer: nil,
      clock: clock
    }

    # A peer with a persistent keepalive sends one immediately when it
    # starts.
    state = if state.persistent_keepalive > 0, do: set_timer(state, :persistent_keepalive, clock.()), else: state
    if state.endpoint, do: send(sealer, {:wg_endpoint, state.endpoint, 0})
    {:ok, arm(state)}
  end

  # The interface sends only responses and cookie replies to the peer.
  @impl true
  def handle_info({:wg_frame, index, frame, source}, state) do
    state = receive_frame(state, index, frame, source)
    Admission.release(state.inbound, 1, byte_size(frame))
    {:noreply, arm(state)}
  end

  # The events of the sealer change the timers, and they can start a
  # handshake.
  def handle_info({:wg_sealed, events, trigger, index, staged}, state) do
    state = Enum.reduce(events, %{state | staged_seen: staged}, &sent_authenticated(&2, &1))
    state = if trigger && not replaced?(state, trigger, index), do: initiate(state, trigger), else: state
    {:noreply, arm(state)}
  end

  # The events of the opener change the timers and the endpoint, and they
  # can confirm a key. The endpoint goes to the sealer before the promotion.
  # Thus the staged packets go to the endpoint that the confirming message
  # can set.
  #
  # The interface admitted the frames of a report with a lower configure
  # number than the peer's before the latest configure message. Their
  # source is older than the configuration, so the peer does not learn it.
  # The opener reports the source of each batch, so a source that is still
  # current comes again with the next one.
  def handle_info({:wg_opened, events, source, confirmed, configured}, state) do
    state = if source && configured >= state.configured, do: learn_endpoint(state, source), else: state
    state = received_authenticated(state)
    state = if :data in events, do: received_data(state), else: state
    state = Enum.reduce(confirmed, state, &promote(&2, &1))
    {:noreply, state |> last_minute_rekey() |> arm()}
  end

  def handle_info(message, state), do: handle(message, state)

  # A trigger from the sealer is about the key that the sealer had. If the
  # peer gave the sealer a newer key after that, the sealer sends with the
  # newer key, and the trigger is out of date. For example, the sealer can
  # stage a packet and report a demand for a key just before it takes the
  # key of a completed handshake.
  #
  # If the peer has no key, a demand always starts a handshake: the packet
  # waits for a key, whichever key the sealer had when it staged the packet.
  # A rekey about a key that the peer discarded is out of date.
  defp replaced?(%{current: %{local_index: current}}, _trigger, index), do: index != current
  defp replaced?(%{current: nil}, :rekey, index), do: index != nil
  defp replaced?(_state, _trigger, _index), do: false

  @impl true
  def format_status(status),
    do: Wagyu.Redact.format_status(status, [:identity, :peer], message: &redact_message/1)

  # The configuration in a configure message holds the preshared key.
  defp redact_message({:wg_configure, %Config.Peer{}}), do: {:wg_configure, :redacted}
  defp redact_message(message), do: message

  defp handle({:wg_handoff, ticket, metadata}, state) do
    Admission.release(state.handoffs, 1, 0)
    {:noreply, state |> accept_handshake(ticket, metadata) |> arm()}
  end

  defp handle(:wg_handoff_abandoned, state) do
    Admission.release(state.handoffs, 1, 0)
    {:noreply, state}
  end

  defp handle({:wg_configure, %Config.Peer{} = peer}, state) do
    old = state.peer
    state = %{state | peer: peer, configured: state.configured + 1}

    state =
      if peer.endpoint != nil and peer.endpoint != old.endpoint,
        do: %{state | endpoint: endpoint(peer.endpoint)},
        else: state

    # The interface ignores the endpoints that the peer reported before
    # this message. Thus the peer reports its current endpoint again.
    if state.endpoint, do: report_endpoint(state)

    state =
      cond do
        peer.persistent_keepalive == old.persistent_keepalive -> state
        peer.persistent_keepalive == 0 -> cancel_timer(%{state | persistent_keepalive: 0}, :persistent_keepalive)
        true -> persistent_keepalive(%{state | persistent_keepalive: peer.persistent_keepalive * 1_000})
      end

    {:noreply, arm(state)}
  end

  # The message comes from the armed process timer, or from a timer that
  # the peer replaced after it armed it. In both cases, only the timers that
  # are already due run.
  defp handle({:wg_timer, tag}, state) do
    state = if match?({^tag, _ref, _deadline}, state.timer), do: %{state | timer: nil}, else: state

    case run_timers(state) do
      {:stop, state} -> {:stop, :normal, state}
      state -> {:noreply, arm(state)}
    end
  end

  # A rekey of the same kind that the timers start. Tests send this message
  # to start a rekey without a wait.
  defp handle(:wg_initiate, state), do: {:noreply, state |> initiate(:rekey) |> arm()}

  # The sealer or the opener could not accept its half of a key pair. That
  # half is gone. If the key pair is `:current` or `:next`, the peer
  # discards it, and starts a handshake for a new key. A key pair that is
  # `:previous` does not send. If the sealer lost its half, the inbound half
  # still opens frames that were delayed. Thus the peer keeps it until it
  # expires.
  defp handle({:wg_key_lost, index}, state) do
    case slot(state, index) do
      {slot, _key_pair} when slot in [:current, :next] ->
        {:noreply, state |> discard([slot]) |> initiate(:rekey) |> arm()}

      _previous_or_gone ->
        {:noreply, state}
    end
  end

  defp handle(_message, state), do: {:noreply, state}

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
    case Noise.write_response(session, index, remote_index, state.mac1_key, cookie(state)) do
      {:ok, frame} ->
        key_pair = key_pair(index, remote_index, state.clock.(), false)

        state =
          state
          |> sent_mac1(frame)
          |> received_authenticated()
          |> install_next(key_pair)
          |> split(session, key_pair, :next)
          |> new_key_pair()

        transmit(%{learn_endpoint(state, source) | received: timestamp}, frame, :responses_sent)

      :error ->
        :ok = Decibel.close(session)
        :ok = Interface.retire_index(state.root, index)
        state
    end
  end

  # Initiating

  # `trigger` has one of these values:
  #
  #   * `:demand` for an outbound packet that must wait for a key. It starts
  #     or extends the attempt.
  #   * `:retry` for the retry timer.
  #   * `:rekey` for all other causes. It joins an attempt that already
  #     runs.
  #
  # While a retry is pending, only the retry sends the next initiation.
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
        frame = Noise.write_initiation(session, index, timestamp, state.mac1_key, cookie(state))
        :ok = wait_for(timestamp)
        initiation = %{session: session, local_index: index, timestamp: timestamp, sent_at: state.clock.()}
        state = %{discard_initiation(state) | initiation: initiation} |> sent_mac1(frame)
        state = transmit(state, frame, :initiations_sent)
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

  # The interface sends transport messages to the opener.
  defp receive_frame(state, index, frame, source) do
    case Packet.decode(frame) do
      {:ok, %Response{} = response} -> response(state, index, response, source)
      {:ok, %CookieReply{} = reply} -> cookie_reply(state, reply)
      _unexpected -> dropped(state)
    end
  end

  # Cookies

  defp cookie_reply(%{last_mac1: <<_::binary-16>> = mac1} = state, reply) do
    case Cookie.open(reply, state.cookie_key, mac1) do
      {:ok, cookie} -> count(%{state | cookie: {cookie, state.clock.()}, last_mac1: nil}, :cookie_replies_accepted)
      :error -> state |> count(:cookie_replies_invalid) |> dropped()
    end
  end

  defp cookie_reply(state, _reply), do: state |> count(:cookie_replies_invalid) |> dropped()

  # The latest cookie while it is younger than COOKIE_REFRESH_TIME, or nil.
  defp cookie(%{cookie: {cookie, received_at}} = state) do
    if state.clock.() - received_at < @cookie_lifetime, do: cookie
  end

  defp cookie(_state), do: nil

  # A cookie reply to a handshake message is encrypted with its MAC1.
  defp sent_mac1(state, frame) do
    {:ok, mac1} = Packet.mac1(frame)
    %{state | last_mac1: mac1}
  end

  defp response(state, index, response, source) do
    with %{local_index: ^index, session: session, sent_at: sent_at} <- state.initiation,
         :ok <- Noise.read_response(session, response) do
      # The initiator's key is as old as its initiation. The responder's key
      # dates from the response, so the initiator's key is never younger. If
      # a response arrives too late, it gives a key that already expired,
      # and the next packet starts a new handshake.
      key_pair = key_pair(index, response.sender_index, sent_at, true)

      # The sealer sends a keepalive if it has no staged packet. This
      # confirms the key to the responder.
      %{learn_endpoint(state, source) | initiation: nil}
      |> received_authenticated()
      |> install_current(key_pair)
      |> split(session, key_pair, true)
      |> new_key_pair()
      |> handshake_complete()
      |> count(:responses_accepted)
    else
      _unmatched_or_unauthenticated -> state |> count(:responses_invalid) |> dropped()
    end
  end

  # An initiator that still receives under a key close to REJECT_AFTER_TIME
  # starts one handshake. Possibly it sends nothing that starts one.
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

  # The peer keeps only the record of each key pair. The sealer and the
  # opener hold its session.
  defp key_pair(local_index, remote_index, created_at, initiator) do
    %{local_index: local_index, remote_index: remote_index, created_at: created_at, initiator: initiator}
  end

  # REJECT_AFTER_TIME: a key that is this old does not send or receive.
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

  # The opener reports the first transport message that authenticates
  # under a key pair that this peer responded to. If that key pair is still
  # `:next`, it becomes `:current`, and the sealer sends under it. A key
  # pair that a newer handshake displaced stays displaced.
  defp promote(%{next: %{local_index: index}} = state, index) do
    send(state.sealer, {:wg_promote, index})
    state |> confirm() |> handshake_complete()
  end

  defp promote(state, _index), do: state

  defp discard(state, slots) do
    Enum.reduce(slots, state, fn slot, state ->
      case Map.fetch!(state, slot) do
        nil ->
          state

        key_pair ->
          # The sealer and the opener close the halves that they hold.
          send(state.sealer, {:wg_discard, key_pair.local_index})
          send(state.opener, {:wg_discard, key_pair.local_index})
          :ok = Interface.retire_index(state.root, key_pair.local_index)
          Map.put(state, slot, nil)
      end
    end)
  end

  # Key pairs older than REJECT_AFTER_TIME cannot accept more messages.
  defp discard_expired(state), do: discard(state, Enum.filter(@slots, &expired?(state, &1)))

  defp expired?(state, slot) do
    case Map.fetch!(state, slot) do
      nil -> false
      key_pair -> not fresh?(state, key_pair)
    end
  end

  # Sending

  # Moves both directions of the session of a completed handshake: the
  # inbound half to the opener and the outbound half to the sealer. `mode`
  # is `:next` for a key pair that waits for the initiator to confirm it.
  # The opener then reports the first message under it. Otherwise the key
  # pair is `:current`, and the sealer sends its staged packets under it. A
  # key that this peer initiated is confirmed by the first transport message
  # under it, so a `mode` of true makes the sealer send a keepalive if it
  # has no staged packet.
  #
  # The peer moves the halves before it sends its response. Thus the opener
  # has the inbound half before the initiator can send under it.
  defp split(state, session, key_pair, mode) do
    %{in: inbound, out: outbound} = Decibel.split(session, %{in: state.opener, out: state.sealer})
    opened = %{local_index: key_pair.local_index, created_at: key_pair.created_at, pending: mode == :next}
    send(state.opener, {:wg_key, inbound, opened})
    send(state.sealer, {:wg_key, outbound, key_pair, mode})
    state
  end

  # The sealer sends a keepalive, which is an empty transport message, if
  # there is a usable key.
  defp send_keepalive(state) do
    if usable(state), do: send(state.sealer, :wg_keepalive)
    state
  end

  # The current key pair while it is younger than REJECT_AFTER_TIME, or nil.
  defp usable(%{current: key_pair} = state) do
    if key_pair && fresh?(state, key_pair), do: key_pair
  end

  # Drops the staged packets that the peer knows of. The sealer counts each
  # one. A packet that the sealer staged after its last report stays: its
  # report, which is on the way, starts a new handshake attempt for it.
  defp drop_staged(state) do
    :ok = Sealer.drop_staged(state.sealer, state.staged_seen)
    state
  end

  # A handshake message starts the REKEY_TIMEOUT wait, also if the send
  # fails. Thus the peer does not try a failed socket again for each packet.
  # The sender counts `event` when it sends the frame, or `:send_errors`.
  defp transmit(state, frame, event) do
    send_frames(state, [{frame, 0}], event)
    sent_authenticated(state, event)
  end

  defp send_frames(%{endpoint: {_address, _port} = endpoint} = state, frames, event),
    do: send(state.sender, {:wg_send, endpoint, frames, event, :outbound})

  # The sealer sends to the endpoint that the peer last gave it.
  defp report_endpoint(state) do
    send(state.sealer, {:wg_endpoint, state.endpoint, state.configured})
    :ok = Interface.endpoint_learned(state.root, state.public_key, state.configured, state.endpoint)
    state
  end

  # Timer events

  defp sent_authenticated(state, event) when event in [:initiations_sent, :responses_sent],
    do: %{state | handshake_sent_at: state.clock.()} |> cancel_timer(:keepalive) |> persistent_keepalive()

  defp sent_authenticated(state, event) do
    state = state |> cancel_timer(:keepalive) |> persistent_keepalive()

    if event == :transport_sent,
      do: set_timer_unless_pending(state, :new_handshake, @keepalive_timeout + @rekey_timeout + jitter()),
      else: state
  end

  defp received_authenticated(state), do: state |> cancel_timer(:new_handshake) |> persistent_keepalive()

  defp received_data(state), do: set_timer_unless_pending(state, :keepalive, @keepalive_timeout)

  defp new_key_pair(state), do: %{set_timer(state, :zero, state.clock.() + @zero_after) | last_minute_rekey: false}

  defp handshake_complete(state), do: state |> cancel_timer(:retry) |> cancel_timer(:give_up)

  defp persistent_keepalive(%{persistent_keepalive: 0} = state), do: state

  defp persistent_keepalive(state),
    do: set_timer(state, :persistent_keepalive, state.clock.() + state.persistent_keepalive)

  # Timers

  # Runs the timers that are due, earliest first, until no timer is due.
  # The peer deletes each timer before it runs, and a timer can set or
  # cancel other timers. Key pairs older than REJECT_AFTER_TIME go first, so
  # no timer sends under one.
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
    |> set_timer_unless_pending(:zero, @zero_after)
  end

  # If the key expired after the data arrived, the peer starts a handshake.
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

  # The interface refuses while it has messages admitted for this process.
  # These messages then arrive and the peer handles them first. The peer
  # asks again later.
  defp exit_if_idle(state) do
    case Interface.release_peer(state.root, state.public_key) do
      :ok -> {:stop, state}
      :busy -> set_timer(state, :zero, state.clock.() + @rekey_timeout)
    end
  end

  defp pending?(state, name), do: Map.has_key?(state.timers, name)

  defp set_timer(state, name, deadline), do: %{state | timers: Map.put(state.timers, name, deadline)}

  # Sets a timer `delay` from now if the timer is not pending. The peer
  # reads the clock only in that case.
  defp set_timer_unless_pending(state, name, delay),
    do: if(pending?(state, name), do: state, else: set_timer(state, name, state.clock.() + delay))

  defp cancel_timer(state, name), do: %{state | timers: Map.delete(state.timers, name)}

  # Up to 333 ms, as in wireguard-go.
  defp jitter, do: :rand.uniform(@max_jitter + 1) - 1

  # Arms the process timer for the earliest deadline, which includes the
  # expiry of each key pair. If a process timer is already armed for that
  # deadline or earlier, the peer keeps it. The peer cancels a timer that is
  # armed for a later time. A timer that fires early finds nothing due and
  # arms the next.
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

  defp learn_endpoint(%{endpoint: endpoint} = state, endpoint), do: state

  defp learn_endpoint(state, endpoint), do: report_endpoint(%{state | endpoint: endpoint})

  defp close(session) do
    :ok = Decibel.close(session)
    :error
  end

  defp count(state, name, increment \\ 1)
  defp count(state, _name, 0), do: state

  defp count(state, name, increment) do
    :ok = Interface.count_peer_event(state.counters, name, increment)
    state
  end

  defp dropped(state), do: %{state | inbound_dropped: state.inbound_dropped + 1}
end
